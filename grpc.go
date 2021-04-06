package sca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/omecodes/errors"
	"net"
	"time"

	"github.com/omecodes/libome"
	"github.com/omecodes/libome/crypt"
)

type csrServerHandler struct {
	ome.UnimplementedCSRServer
}

func (h *csrServerHandler) SignCertificate(ctx context.Context, in *ome.SignCertificateRequest) (*ome.SignCertificateResponse, error) {
	cred := ome.ProxyCredentialsFromContext(ctx)
	if cred == nil {
		return nil, errors.Forbidden("missing proxy credentials")
	}

	man := manager(ctx)
	if man == nil {
		return nil, errors.New("missing credentials manager in context")
	}

	secret, err := man.GetSecret(cred.Key)
	if err != nil {
		return nil, err
	}

	if secret != cred.Secret {
		return nil, errors.Unauthorized("Authentication failed")
	}

	var ips []net.IP
	for _, a := range in.Csr.Addresses {
		ips = append(ips, net.ParseIP(a))
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), in.Csr.PublicKey)
	k := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	signerCert := certificate(ctx)
	if signerCert == nil {
		return nil, errors.Unauthorized("missing signer certificate in context")
	}

	signerKey := key(ctx)
	if signerKey == nil {
		return nil, errors.Unauthorized("missing signer key in context")
	}

	cert, err := crypt.GenerateServiceCertificate(&crypt.CertificateTemplate{
		Name:              in.Csr.Subject,
		SignerCertificate: signerCert,
		SignerPrivateKey:  signerKey,
		PublicKey:         k,
		Domains:           in.Csr.Domains,
		IPs:               ips,
		Expiry:            time.Hour * 24 * 730,
	})
	if err != nil {
		return nil, err
	}

	return &ome.SignCertificateResponse{
		RawCertificate: cert.Raw,
	}, nil
}
