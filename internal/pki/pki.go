package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type Authority struct {
	caCert    *x509.Certificate
	caKey     *rsa.PrivateKey
	caPEM     []byte
	panelCert tls.Certificate
}

func LoadOrCreate(dir, commonName string) (*Authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir pki dir: %w", err)
	}

	caCertPath := filepath.Join(dir, "ca.pem")
	caKeyPath := filepath.Join(dir, "ca-key.pem")
	panelCertPath := filepath.Join(dir, "panel.pem")
	panelKeyPath := filepath.Join(dir, "panel-key.pem")

	if exists(caCertPath) && exists(caKeyPath) && exists(panelCertPath) && exists(panelKeyPath) {
		caPEM, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("read ca cert: %w", err)
		}
		caKeyPEM, err := os.ReadFile(caKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read ca key: %w", err)
		}
		caCert, caKey, err := parseCA(caPEM, caKeyPEM)
		if err != nil {
			return nil, err
		}
		panelCert, err := tls.LoadX509KeyPair(panelCertPath, panelKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load panel tls keypair: %w", err)
		}
		if !panelCertificateCoversHost(panelCert, commonName) {
			panelCert, err = writePanelCertificate(dir, commonName, caCert, caKey)
			if err != nil {
				return nil, err
			}
		}
		return &Authority{caCert: caCert, caKey: caKey, caPEM: caPEM, panelCert: panelCert}, nil
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   commonName + " CA",
			Organization: []string{"mgb-panel"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create ca certificate: %w", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)})

	panelKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generate panel key: %w", err)
	}
	dnsNames := []string{"localhost"}
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1")}
	if ip := net.ParseIP(commonName); ip != nil {
		ipAddresses = append(ipAddresses, ip)
	} else if commonName != "" && commonName != "localhost" {
		dnsNames = append(dnsNames, commonName)
	}

	panelTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"mgb-panel"},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().AddDate(3, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
	}
	panelDER, err := x509.CreateCertificate(rand.Reader, panelTemplate, caTemplate, &panelKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create panel certificate: %w", err)
	}
	panelCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: panelDER})
	panelKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(panelKey)})

	for _, file := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{caCertPath, caPEM, 0o644},
		{caKeyPath, caKeyPEM, 0o600},
		{panelCertPath, panelCertPEM, 0o644},
		{panelKeyPath, panelKeyPEM, 0o600},
	} {
		if err := os.WriteFile(file.path, file.data, file.mode); err != nil {
			return nil, fmt.Errorf("write %s: %w", file.path, err)
		}
	}
	panelCert, err := tls.LoadX509KeyPair(panelCertPath, panelKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load created panel keypair: %w", err)
	}
	caCert, caKeyParsed, err := parseCA(caPEM, caKeyPEM)
	if err != nil {
		return nil, err
	}
	return &Authority{caCert: caCert, caKey: caKeyParsed, caPEM: caPEM, panelCert: panelCert}, nil
}

func (a *Authority) TLSConfig() (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(a.caPEM) {
		return nil, fmt.Errorf("append ca to client pool")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{
			a.panelCert,
		},
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  pool,
	}, nil
}

func (a *Authority) UseServerCertificate(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load external tls keypair: %w", err)
	}
	a.panelCert = cert
	return nil
}

func (a *Authority) CAPEM() []byte {
	return append([]byte(nil), a.caPEM...)
}

func (a *Authority) FingerprintHex() string {
	sum := sha256.Sum256(a.caCert.Raw)
	return hex.EncodeToString(sum[:])
}

func (a *Authority) SignNodeCSR(csrPEM []byte, nodeID string, ttl time.Duration) ([]byte, string, time.Time, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, "", time.Time{}, fmt.Errorf("invalid csr pem")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, "", time.Time{}, fmt.Errorf("check csr signature: %w", err)
	}

	serialNum, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("generate serial: %w", err)
	}
	notAfter := time.Now().Add(ttl)
	template := &x509.Certificate{
		SerialNumber: serialNum,
		Subject: pkix.Name{
			CommonName:   nodeID,
			Organization: []string{"mgb-panel-node"},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.caCert, csr.PublicKey, a.caKey)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("create node certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), serialNum.Text(16), notAfter.UTC(), nil
}

func VerifyClientCertificate(raw *tls.ConnectionState) (string, error) {
	if raw == nil || len(raw.PeerCertificates) == 0 {
		return "", fmt.Errorf("missing client certificate")
	}
	cert := raw.PeerCertificates[0]
	if cert.Subject.CommonName == "" {
		return "", fmt.Errorf("client certificate missing common name")
	}
	return cert.Subject.CommonName, nil
}

func panelCertificateCoversHost(cert tls.Certificate, host string) bool {
	if len(cert.Certificate) == 0 || host == "" {
		return true
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}
	return leaf.VerifyHostname(host) == nil
}

func writePanelCertificate(dir, commonName string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (tls.Certificate, error) {
	panelKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate panel key: %w", err)
	}
	dnsNames := []string{"localhost"}
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1")}
	if ip := net.ParseIP(commonName); ip != nil {
		ipAddresses = append(ipAddresses, ip)
	} else if commonName != "" && commonName != "localhost" {
		dnsNames = append(dnsNames, commonName)
	}
	panelTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"mgb-panel"},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().AddDate(3, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
	}
	panelDER, err := x509.CreateCertificate(rand.Reader, panelTemplate, caCert, &panelKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create panel certificate: %w", err)
	}
	panelCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: panelDER})
	panelKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(panelKey)})
	panelCertPath := filepath.Join(dir, "panel.pem")
	panelKeyPath := filepath.Join(dir, "panel-key.pem")
	if err := os.WriteFile(panelCertPath, panelCertPEM, 0o644); err != nil {
		return tls.Certificate{}, fmt.Errorf("write %s: %w", panelCertPath, err)
	}
	if err := os.WriteFile(panelKeyPath, panelKeyPEM, 0o600); err != nil {
		return tls.Certificate{}, fmt.Errorf("write %s: %w", panelKeyPath, err)
	}
	panelCert, err := tls.LoadX509KeyPair(panelCertPath, panelKeyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load panel tls keypair: %w", err)
	}
	return panelCert, nil
}

func parseCA(certPEM, keyPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("decode ca cert")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("decode ca key")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca key: %w", err)
	}
	return cert, key, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
