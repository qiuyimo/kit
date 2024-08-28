package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme/autocert"
)

// httpsCmd represents the https command
var httpsCmd = &cobra.Command{
	Use:   "https",
	Short: "https",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("https called")
		engine := gin.New()
		engine.Any("/", func(ctx *gin.Context) {
			ctx.String(http.StatusOK, "clientIP: "+ctx.ClientIP())
		})

		httpsServer := &http.Server{
			Handler: engine,
		}

		tlsAddr := ":8888"

		tlsConfig := getTlsCfg()
		listen, err := tls.Listen("tcp", tlsAddr, tlsConfig)
		if err != nil {
			log.Panicf("tls.Listen err: %v", err)
		}
		err = httpsServer.Serve(listen)
		if err != nil {
			log.Panicf("httpsServer.Serve(listen) error: %v", err)
			return
		}
	},
}

func init() {
	rootCmd.AddCommand(httpsCmd)
}

func getTlsCfg() *tls.Config {
	return &tls.Config{
		GetCertificate: func(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := getCertificateByDomain(helloInfo)
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
}

func getCertificateByDomain(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	AcmeCertManager := autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache("certs"),
	}

	if helloInfo.ServerName == "" {
		return getDefaultCertificate()
	}
	// autocert
	tlsCert, err := AcmeCertManager.GetCertificate(helloInfo)
	if err != nil {
		return nil, err
	}
	return tlsCert, err
}

var defaultCert *tls.Certificate

func getDefaultCertificate() (*tls.Certificate, error) {
	if defaultCert != nil {
		return defaultCert, nil
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"sag"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(100, 0, 0), // 有效期为100年
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	var certificate tls.Certificate
	certificate.Certificate = append(certificate.Certificate, derBytes)
	certificate.PrivateKey = privateKey

	defaultCert = &certificate

	return &certificate, nil
}
