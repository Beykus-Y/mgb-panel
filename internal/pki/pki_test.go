package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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
