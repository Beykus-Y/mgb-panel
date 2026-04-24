package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"os"
	"testing"
	"time"
)

func TestLoadOrCreateAndSignNodeCSR(t *testing.T) {
	dir := t.TempDir()
	auth, err := LoadOrCreate(dir, "panel.local")
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if len(auth.CAPEM()) == 0 {
		t.Fatal("expected ca pem")
	}

	nodeKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "node-test"},
	}, nodeKey)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	certPEM, serial, notAfter, err := auth.SignNodeCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), "node-test", 24*time.Hour)
	if err != nil {
		t.Fatalf("SignNodeCSR: %v", err)
	}
	if serial == "" || len(certPEM) == 0 || notAfter.Before(time.Now()) {
		t.Fatal("unexpected certificate result")
	}

	if _, err := os.Stat(dir + "/panel.pem"); err != nil {
		t.Fatalf("panel certificate not persisted: %v", err)
	}
}

func TestLoadOrCreateAddsIPSANForPanelHost(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreate(dir, "203.0.113.10"); err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(dir+"/panel.pem", dir+"/panel-key.pem")
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	want := net.ParseIP("203.0.113.10")
	for _, ip := range parsed.IPAddresses {
		if ip.Equal(want) {
			return
		}
	}
	t.Fatalf("panel certificate missing IP SAN %s: %v", want, parsed.IPAddresses)
}
