package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/omecodes/common/env/app"
	"github.com/omecodes/common/utils/log"
	"github.com/omecodes/common/utils/prompt"
	"github.com/omecodes/libome"
	"github.com/omecodes/libome/crypt"
	"github.com/omecodes/libome/ports"
	"github.com/omecodes/service"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
	"path/filepath"
)

var (
	Vendor       = "Ome"
	Version      = "1.0.0"
	services     = []string{"discovery", "accounts", "tokens", "apps"}
	domain       string
	ip, eip      string
	gPort        int
	certFilename string
	keyFilename  string
	cmd          *cobra.Command
	application  *app.App
	passwords    map[string]string
)

func init() {
	application = app.New(Vendor, "Services-CA",
		app.WithVersion(Version),
		app.WithRunCommandFunc(start),
	)
	err := application.InitDirs()
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	passwords = map[string]string{}
	passwordsFilename := filepath.Join(application.DataDir(), "passwords.json")
	stats, err := os.Stat(passwordsFilename)
	if err != nil && !os.IsNotExist(err) {
		fmt.Println(err)
		os.Exit(-1)
	}

	if stats != nil {
		data, err := ioutil.ReadFile(passwordsFilename)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		err = json.Unmarshal(data, &passwords)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
	} else {
		for _, name := range services {
			passwords[name] = crypt.NewPassword(16)
		}

		data, err := json.Marshal(passwords)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		err = ioutil.WriteFile(passwordsFilename, data, os.ModePerm)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
	}

	cmd = application.GetCommand()

	flags := application.StartCommand().PersistentFlags()

	flags.StringVar(&domain, "dn", "", "Domain name (required)")
	flags.StringVar(&ip, "ip", "", "IP address to bind server to (required)")
	flags.StringVar(&eip, "eip", "", "External IP address")
	flags.IntVar(&gPort, "grpc", ports.Ome, "gRPC server port")
	flags.StringVar(&certFilename, "cert", "", "Certificate file path")
	flags.StringVar(&keyFilename, "key", "", "Key file path")

	_ = cobra.MarkFlagRequired(flags, "domain")
	_ = cobra.MarkFlagRequired(flags, "ip")
	_ = cobra.MarkFlagRequired(flags, "dsn")
}

func start() {
	if ip == "" || domain == "" {
		sc := application.StartCommand()
		_ = sc.Help()
		os.Exit(-1)
	}

	var boxParams service.Params

	boxParams.Dir = application.DataDir()
	boxParams.Name = "sca"
	boxParams.CA = true
	boxParams.Domain = domain
	boxParams.NoRegistry = true
	boxParams.Ip = ip
	if eip != "" && eip != ip {
		boxParams.ExternalIp = eip
	}
	boxParams.CertificatePath = certFilename
	boxParams.KeyPath = keyFilename

	box, err := service.CreateBox(context.Background(), &boxParams)
	if err != nil {
		log.Fatal("Services CA • could not create box", log.Err(err))
	}

	err = box.StartCAService(func(credentials *ome.ProxyCredentials) (bool, error) {
		pass, found := passwords[credentials.Key]
		return found && pass == credentials.Secret, nil
	})
	if err != nil {
		log.Error("Services CA • could not start CA service", log.Err(err))
		os.Exit(-1)
	}

	defer box.Stop()
	<-prompt.QuitSignal()
}

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}