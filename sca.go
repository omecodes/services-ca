package sca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/gorilla/mux"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	grpc_opentracing "github.com/grpc-ecosystem/go-grpc-middleware/tracing/opentracing"
	"github.com/omecodes/common/utils/log"
	ome "github.com/omecodes/libome"
	"github.com/omecodes/libome/crypt"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	if err != nil {
		return os.IsExist(err)
	}
	return true
}

type ServerConfig struct {
	Manager      CredentialsManager
	Domain       string
	PublicIP     string
	GRPCPort     int
	HTTPPort     int
	BindIP       string
	CertFilename string
	KeyFilename  string
	WorkingDir   string
}

func NewServer(cfg *ServerConfig) *Server {
	return &Server{
		config: cfg,
	}
}

type Server struct {
	config *ServerConfig

	adminPassword string
	privateKey    crypto.PrivateKey
	certificate   *x509.Certificate
	listener      net.Listener
	Errs          chan error
}

func (s *Server) loadOrGenerateSigningKeyPair() (err error) {
	if s.certificate != nil && s.privateKey != nil {
		return nil
	}

	certificateFilename := filepath.Join(s.config.WorkingDir, "ca.crt")
	keyFilename := filepath.Join(s.config.WorkingDir, "ca.key")

	shouldGenerateNewPair := !fileExists(certificateFilename) || !fileExists(keyFilename)
	if !shouldGenerateNewPair {
		s.privateKey, err = crypt.LoadPrivateKey([]byte{}, keyFilename)
		if err != nil {
			return fmt.Errorf("could not load private key: %s", err)
		}

		s.certificate, err = crypt.LoadCertificate(certificateFilename)
		if err != nil {
			return fmt.Errorf("could not load certificate: %s", err)
		}
		return
	}

	if shouldGenerateNewPair {
		s.privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("could not generate key pair: %s", err)
		}
		pub := s.privateKey.(*ecdsa.PrivateKey).PublicKey

		caCertTemplate := &crypt.CertificateTemplate{
			Organization:     "oe",
			Name:             "CA",
			Domains:          []string{s.config.Domain},
			IPs:              []net.IP{},
			Expiry:           time.Hour * 24 * 370,
			PublicKey:        &pub,
			SignerPrivateKey: s.privateKey,
		}
		caCertTemplate.IPs = append(caCertTemplate.IPs, net.ParseIP(s.config.PublicIP))

		s.certificate, err = crypt.GenerateCACertificate(caCertTemplate)
		if err != nil {
			return fmt.Errorf("could not generate CA cert: %s", err)
		}

		_ = crypt.StoreCertificate(s.certificate, certificateFilename, os.ModePerm)
		_ = crypt.StorePrivateKey(s.privateKey, nil, keyFilename)
	}
	return
}

func (s *Server) Start() error {
	s.Errs = make(chan error, 1)

	adminPasswordFile := filepath.Join(s.config.WorkingDir, "admin-psswd")
	data, err := ioutil.ReadFile(adminPasswordFile)
	if err != nil {
		s.adminPassword = string(data)
	} else {
		s.adminPassword = crypt.NewPassword(16)
		_ = ioutil.WriteFile(adminPasswordFile, []byte(s.adminPassword), os.ModePerm)
	}

	err = s.loadOrGenerateSigningKeyPair()
	if err != nil {
		return err
	}

	var tc *tls.Config
	certPEMBytes, _ := crypt.PEMEncodeCertificate(s.certificate)
	keyPEMBytes, _ := crypt.PEMEncodeKey(s.privateKey)
	tlsCert, err := tls.X509KeyPair(certPEMBytes, keyPEMBytes)
	if err == nil {
		clientCAs := x509.NewCertPool()
		clientCAs.AddCert(s.certificate)
		tc = &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			ClientCAs:    clientCAs,
			ClientAuth:   tls.VerifyClientCertIfGiven,
		}
	} else {
		log.Error("could not load TLS configs", log.Err(err))
		return err
	}

	gRPCAddress := fmt.Sprintf("%s:%d", s.config.BindIP, s.config.GRPCPort)
	s.listener, err = tls.Listen("tcp", gRPCAddress, tc)
	if err != nil {
		return err
	}

	log.Info("starting gRPC server", log.Field("service", "CA"), log.Field("at", gRPCAddress))
	var opts []grpc.ServerOption

	defaultInterceptor := ome.NewGrpcContextInterceptor(
		ome.NewProxyBasicInterceptor(),
		ome.GrpcContextUpdaterFunc(func(ctx context.Context) (context.Context, error) {
			ctx = ContextWithCert(ctx, s.certificate)
			ctx = ContextWithKey(ctx, s.privateKey)
			return ContextWithManager(ctx, s.config.Manager), nil
		}),
	)

	logger, _ := zap.NewProduction()
	chainUnaryInterceptor := grpc_middleware.ChainUnaryServer(
		defaultInterceptor.UnaryUpdate,
		grpc_opentracing.UnaryServerInterceptor(),
		grpc_zap.UnaryServerInterceptor(logger),
	)

	opts = append(opts, grpc.UnaryInterceptor(chainUnaryInterceptor))
	srv := grpc.NewServer(opts...)
	ome.RegisterCSRServer(srv, &csrServerHandler{})

	go func() {
		if err := srv.Serve(s.listener); err != nil {
			log.Error("failed to serve CA", log.Err(err))
		}
	}()

	router := mux.NewRouter()
	router.Path("/ca.crt").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		certificateFilename := filepath.Join(s.config.WorkingDir, "ca.crt")

		data, err := ioutil.ReadFile(certificateFilename)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-type", "text/plain")
		_, _ = w.Write(data)
	})

	address := fmt.Sprintf("%s:%d", s.config.BindIP, s.config.HTTPPort)

	go func() {
		if s.config.CertFilename != "" {
			s.Errs <- http.ListenAndServeTLS(address, s.config.CertFilename, s.config.KeyFilename, router)
		} else {
			s.Errs <- http.ListenAndServe(address, router)
		}
	}()
	return nil
}

func (s *Server) Stop() error {
	return s.listener.Close()
}
