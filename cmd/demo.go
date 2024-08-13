package cmd

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme/autocert"
)

// demoCmd represents the demo command
var demoCmd = &cobra.Command{
	Use:   "demo",
	Short: "demo",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("demo called")

		ipCIDR := "192.168.3.218/24"
		ip, _, err := net.ParseCIDR(ipCIDR)
		if err != nil {
			panic(err)
		}
		isNil := ip.To16() == nil
		fmt.Println(isNil) // false

		// engine := gin.New()
		//
		// engine.Any("/", func(ctx *gin.Context) {
		// 	ctx.JSON(http.StatusOK, gin.H{"a": "a"})
		// })
		// TlsServer(engine)

		// str := "192.168.11.1/24"
		// s := str[strings.LastIndex(str, "/")+1:]
		// firstSubnetMask := s[strings.LastIndex(s, "/")+1:]
		//
		// res := true
		// if firstSubnetMask[0] < '1' || firstSubnetMask[0] > '9' {
		// 	res = false
		// }
		//
		// // res := unicode.IsDigit(rune(s[0]))
		// fmt.Println(res)
	},
}

func init() {
	rootCmd.AddCommand(demoCmd)
}

func TlsServer(engine *gin.Engine) {
	tlsConfig := &tls.Config{
		GetCertificate: func(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := getCertificateByDomainV2(helloInfo)
			return cert, err
		},
		NextProtos: []string{"h2", "http/1.1"},
		MaxVersion: tls.VersionTLS13,
		MinVersion: tls.VersionTLS11,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		},
	}

	host := ":8888"
	listen, err := tls.Listen("tcp", host, tlsConfig)
	if err != nil {
		os.Exit(1)
	}
	err = http.Serve(listen, engine)
	if err != nil {
		os.Exit(1)
	}
	defer listen.Close()
}
func getCertificateByDomainV2(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var AcmeCertManager = autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache("certs"),
	}

	tls, err := AcmeCertManager.GetCertificate(helloInfo)
	if err != nil {
		return nil, err
	}
	return tls, err
}
