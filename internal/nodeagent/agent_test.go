package nodeagent

import (
	"testing"
)

func TestPEMFingerprintRejectsGarbage(t *testing.T) {
	if _, err := pemFingerprint([]byte("not a pem")); err == nil {
		t.Fatal("expected pem decode failure")
	}
}
