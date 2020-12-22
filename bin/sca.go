package main

import (
	"fmt"
	"github.com/omecodes/common/utils/prompt"
	"github.com/omecodes/libome/ports"
	sca "github.com/omecodes/services-ca"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
)

var (
	domain       string
	ip, eip      string
	gPort        int
	hPort        int
	certFilename string
	keyFilename  string
	secret       string
	workingDir   string
	cmd          *cobra.Command
)

func init() {
	var err error
	workingDir, err = filepath.Abs("./")
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	cmd = &cobra.Command{
		Use:   filepath.Base(os.Args[0]),
		Short: "Starts CA service",
		Run:   start,
	}

	flags := cmd.PersistentFlags()

	flags.StringVar(&domain, "dn", "", "Domain name (required)")
	flags.StringVar(&ip, "ip", "", "IP address to bind server to (required)")
	flags.StringVar(&eip, "eip", "", "External IP address")
	flags.IntVar(&hPort, "http", 8080, "gRPC server port")
	flags.IntVar(&gPort, "grpc", ports.CA, "gRPC server port")
	flags.StringVar(&secret, "secret", "", "Signing API secret")
	flags.StringVar(&certFilename, "cert", "", "Certificate file path")
	flags.StringVar(&keyFilename, "key", "", "Key file path")

	_ = cobra.MarkFlagRequired(flags, "dn")
	_ = cobra.MarkFlagRequired(flags, "ip")
	_ = cobra.MarkFlagRequired(flags, "secret")
}

func start(cmd *cobra.Command, args []string) {
	if eip == "" {
		eip = ip
	}

	cfg := &sca.ServerConfig{
		Manager: sca.CredentialsManagerFunc(func(s string) (string, error) {
			return secret, nil
		}),
		Domain:       domain,
		PublicIP:     eip,
		GRPCPort:     gPort,
		HTTPPort:     hPort,
		BindIP:       ip,
		CertFilename: certFilename,
		KeyFilename:  keyFilename,
		WorkingDir:   workingDir,
	}

	server := sca.NewServer(cfg)

	err := server.Start()
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	defer func() {
		if err := server.Stop(); err != nil {
			fmt.Println(err)
		}
	}()

	select {
	case <-prompt.QuitSignal():
	case <-server.Errs:
	}
}

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
