package cmd

import (
	"fmt"
	"kit/internal/cert"

	"github.com/spf13/cobra"
)

var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "generate cert、ca",
	Example: `
	# 生成 CA
	kit cert -g -t ~/certs/local_test

	# 生成 cert
	kit cert -k ~/certs/local_test/ca.key -c ~/certs/local_test/ca.crt -t ~/certs/local_test -i 127.0.0.1 -d localhost
	`,
	Run: func(cmd *cobra.Command, args []string) {
		caKey, _ := cmd.Flags().GetString("ca-key")
		caCert, _ := cmd.Flags().GetString("ca-cert")
		targetDir, _ := cmd.Flags().GetString("target-dir")
		serverIps, _ := cmd.Flags().GetStringSlice("server-ips")
		serverDomains, _ := cmd.Flags().GetStringSlice("server-domains")

		generateCa, _ := cmd.Flags().GetBool("generate-ca")

		fmt.Println("caKey: ", caKey)
		fmt.Println("caCert: ", caCert)
		fmt.Println("targetDir: ", targetDir)
		fmt.Println("serverIps: ", serverIps)
		fmt.Println("serverDomains: ", serverDomains)

		if generateCa {
			cert.GenerateCAAndSaveToFile(targetDir)
			return
		}

		cert.GenerateCertsToFileByCA(caKey, caCert, targetDir, serverIps, serverDomains)
	},
}

func init() {
	rootCmd.AddCommand(certCmd)

	certCmd.Flags().StringP("ca-key", "k", "", "ca key")
	certCmd.Flags().StringP("ca-cert", "c", "", "ca cert")
	certCmd.Flags().StringP("target-dir", "t", "", "target dir")
	certCmd.Flags().StringSliceP("server-ips", "i", []string{}, "server ips")
	certCmd.Flags().StringSliceP("server-domains", "d", []string{}, "server domains")

	certCmd.Flags().BoolP("generate-ca", "g", false, "generate ca")
}
