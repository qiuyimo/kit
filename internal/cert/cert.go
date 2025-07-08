package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CA struct {
	caCert       *x509.Certificate
	caPrivKey    *rsa.PrivateKey
	caCertPEM    string
	caPrivKeyPEM string
}

// GenerateCA 生成 CA 证书和私钥
func GenerateCA() (*CA, error) {
	// 生成 CA 私钥
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA private key: %v", err)
	}

	// 创建 CA 证书模板
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "My Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(999, 0, 0), // 过期时间
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// 生成 CA 证书
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %v", err)
	}

	// 解析 CA 证书
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// 将证书转换为 PEM 格式
	caCertPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	}))

	// 将私钥转换为 PEM 格式
	caPrivKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	}))

	return &CA{
		caCert:       caCert,
		caPrivKey:    caPrivKey,
		caCertPEM:    caCertPEM,
		caPrivKeyPEM: caPrivKeyPEM,
	}, nil
}

type GenerateCertsRes struct {
	ServerCertPEM    string
	ServerPrivKeyPEM string
	ClientCertPEM    string
	ClientPrivKeyPEM string
	CaCertPEM        string
}

type GenerateCertsParms struct {
	CaCert         *x509.Certificate
	CaPrivKey      *rsa.PrivateKey
	ServerIPs      []string
	ServerDNSNames []string
}

// 生成 CA，保存到指定文件
func GenerateCAAndSaveToFile(targetDir string) error {
	// targetDir 不存在，就创建
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %v", err)
	}

	ca, err := GenerateCA()
	if err != nil {
		return fmt.Errorf("failed to generate CA: %v", err)
	}

	// 保存 ca.crt 和 ca.key 到 targetDir
	os.WriteFile(filepath.Join(targetDir, "ca.crt"), []byte(ca.caCertPEM), 0644)
	os.WriteFile(filepath.Join(targetDir, "ca.key"), []byte(ca.caPrivKeyPEM), 0600)

	return nil
}

func GenerateCertsToFileByCA(caKeyPath, caCertPath, targetDir string, serverIPs, domains []string) error {
	// targetDir 不存在，就创建
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %v", err)
	}

	// 读取 caCertPath 和 caKeyPath 文件，转换为 x509.Certificate 和 *rsa.PrivateKey
	certPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %v", err)
	}
	// 解码 PEM
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return errors.New("failed to decode certificate PEM")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	keyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read CA private key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return errors.New("failed to decode key PEM")
	}
	var privateKey *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		key, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			return fmt.Errorf("failed to parse PKCS8 private key: %w", err2)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return errors.New("not an RSA private key")
		}
	default:
		return fmt.Errorf("unsupported key type: %s", keyBlock.Type)
	}
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// 调用 GenerateCerts 生成证书
	params := GenerateCertsParms{
		CaCert:         caCert,
		CaPrivKey:      privateKey,
		ServerIPs:      serverIPs,
		ServerDNSNames: domains,
	}

	certs, err := GenerateCerts(params)
	if err != nil {
		return fmt.Errorf("failed to generate certificates: %v", err)
	}

	if err := SaveToTargetDir(targetDir, certs); err != nil {
		return fmt.Errorf("failed to save certificates to target directory: %v", err)
	}

	return nil
}

func GenerateCertsToFile(fileDir string, serverIPs []string) error {
	// 调用 GenerateCA
	ca, err := GenerateCA()
	if err != nil {
		return fmt.Errorf("failed to generate CA: %v", err)
	}

	params := GenerateCertsParms{
		CaCert:    ca.caCert,
		CaPrivKey: ca.caPrivKey,
		ServerIPs: serverIPs,
	}

	// Generate certificates
	certs, err := GenerateCerts(params)
	if err != nil {
		return fmt.Errorf("failed to generate certificates: %v", err)
	}

	if err := SaveToTargetDir(fileDir, certs); err != nil {
		return fmt.Errorf("failed to save certificates to target directory: %v", err)
	}

	return nil
}

func SaveToTargetDir(fileDir string, certs *GenerateCertsRes) error {
	// Create files and write PEM data
	files := map[string]string{
		"ca.crt": certs.CaCertPEM,
		// "ca.key":     ca.caPrivKeyPEM,
		"server.crt": certs.ServerCertPEM,
		"server.key": certs.ServerPrivKeyPEM,
		"client.crt": certs.ClientCertPEM,
		"client.key": certs.ClientPrivKeyPEM,
	}

	for filename, data := range files {
		filepath := fmt.Sprintf("%s/%s", fileDir, filename)
		if strings.HasSuffix(filename, ".crt") {
			// 是 crt 文件，则设置权限为 0644
			err := os.WriteFile(filepath, []byte(data), 0644)
			if err != nil {
				return fmt.Errorf("failed to write %s: %v", filename, err)
			}
		} else {
			// 是 key 文件，则设置权限为 0600
			err := os.WriteFile(filepath, []byte(data), 0600)
			if err != nil {
				return fmt.Errorf("failed to write %s: %v", filename, err)
			}
		}
	}

	return nil
}

// GeneratetCerts 生成服务器和客户端证书, 参数包含有效期，服务器的 ip 地址，域名
func GenerateCerts(params GenerateCertsParms) (*GenerateCertsRes, error) {
	// 生成服务器私钥
	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server private key: %v", err)
	}

	// 把 serverIPs 转换为 []net.IP
	serverIPs := make([]net.IP, 0)
	for _, ip := range params.ServerIPs {
		serverIPs = append(serverIPs, net.ParseIP(ip))
	}

	// 创建服务器证书模板
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "server",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(999, 0, 0), // 过期时间
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, // 可用于客户端和服务端
		BasicConstraintsValid: true,
		IPAddresses:           serverIPs,
		DNSNames:              params.ServerDNSNames,
	}

	// 生成服务器证书
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, params.CaCert, &serverPrivKey.PublicKey, params.CaPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %v", err)
	}

	// 生成客户端私钥
	clientPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client private key: %v", err)
	}

	// 创建客户端证书模板
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "client",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(999, 0, 0), // 过期时间
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, // 可用于客户端和服务端
		BasicConstraintsValid: true,
	}

	// 生成客户端证书
	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, params.CaCert, &clientPrivKey.PublicKey, params.CaPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate: %v", err)
	}

	// 将证书转换为 PEM 格式
	serverCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertDER,
	})
	clientCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCertDER,
	})

	// 将私钥转换为 PEM 格式
	serverPrivKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey),
	})
	clientPrivKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(clientPrivKey),
	})

	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: params.CaCert.Raw,
	})

	return &GenerateCertsRes{
		ServerCertPEM:    string(serverCertPEM),
		ServerPrivKeyPEM: string(serverPrivKeyPEM),
		ClientCertPEM:    string(clientCertPEM),
		ClientPrivKeyPEM: string(clientPrivKeyPEM),
		CaCertPEM:        string(caCertPEM),
	}, nil
}

func IsValidPEMCertificate(certPEM []byte) bool {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}
	_, err := x509.ParseCertificate(block.Bytes)
	return err == nil
}

func IsValidPEMPrivateKey(pemData []byte) bool {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return false
	}

	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		_, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		err = errors.New("未知私钥类型: " + block.Type)
	}

	return err == nil
}
