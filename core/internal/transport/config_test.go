package transport

import (
	"os"
	"testing"
)

func TestLoadCACrt(t *testing.T) {
	// Create a temporary CA cert file
	tmpFile, err := os.CreateTemp("", "ca-cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	certContent := []byte("-----BEGIN CERTIFICATE-----\nFAKE_CERT_CONTENT\n-----END CERTIFICATE-----")
	if _, err := tmpFile.Write(certContent); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	// Save original CaCrtFile path and restore it after test
	originalCaCrtFile := CaCrtFile
	defer func() { CaCrtFile = originalCaCrtFile }()

	// Set CaCrtFile to our temp file
	CaCrtFile = tmpFile.Name()

	// Test LoadCACrt
	if err := LoadCACrt(); err != nil {
		t.Errorf("LoadCACrt failed: %v", err)
	}

	// Verify CACrtPEM content
	if string(CACrtPEM) != string(certContent) {
		t.Errorf("CACrtPEM content mismatch. Got %s, want %s", CACrtPEM, certContent)
	}

	// Test with non-existent file
	CaCrtFile = "/non/existent/file.pem"
	if err := LoadCACrt(); err == nil {
		t.Error("LoadCACrt should have failed with non-existent file")
	}
}
