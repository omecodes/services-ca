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
	domain     string
	ip         string
	port       int
	secret     string
	workingDir string
	cmd        *cobra.Command
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
	flags.IntVar(&port, "grpc", ports.CA, "gRPC server port")
	flags.StringVar(&secret, "secret", "", "Signing API secret")

	_ = cobra.MarkFlagRequired(flags, "dn")
	_ = cobra.MarkFlagRequired(flags, "ip")
	_ = cobra.MarkFlagRequired(flags, "secret")
}

func start(cmd *cobra.Command, args []string) {
	cfg := &sca.ServerConfig{
		Manager: sca.CredentialsManagerFunc(func(s string) (string, error) {
			return secret, nil
		}),
		Domain:     domain,
		Port:       port,
		BindIP:     ip,
		WorkingDir: workingDir,
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
