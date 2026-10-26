package transport

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestReloadServerTLSCertPicksUpNewName(t *testing.T) {
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca-cert.pem")
	caKey := filepath.Join(dir, "ca-key.pem")
	serverCert := filepath.Join(dir, "server-cert.pem")
	serverKey := filepath.Join(dir, "server-key.pem")

	previousCrt, previousKey := ServerCrtFile, ServerKeyFile
	previousCACrt, previousCAKey := CaCrtFile, CaKeyFile
	ServerCrtFile, ServerKeyFile = serverCert, serverKey
	CaCrtFile, CaKeyFile = caCert, caKey
	t.Cleanup(func() {
		ServerCrtFile, ServerKeyFile = previousCrt, previousKey
		CaCrtFile, CaKeyFile = previousCACrt, previousCAKey
	})

	if _, err := GenCerts(nil, caCert, caKey, "", "", true); err != nil {
		t.Fatalf("GenCerts CA: %v", err)
	}
	if _, err := GenCerts([]string{"old.example.com"}, serverCert, serverKey, caKey, caCert, false); err != nil {
		t.Fatalf("GenCerts server: %v", err)
	}
	if err := ReloadServerTLSCert(); err != nil {
		t.Fatalf("ReloadServerTLSCert: %v", err)
	}

	parseNames := func() []string {
		t.Helper()
		cert, err := GetServerTLSCert(nil)
		if err != nil {
			t.Fatalf("GetServerTLSCert: %v", err)
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("parse leaf: %v", err)
		}
		return leaf.DNSNames
	}
	if got := parseNames(); len(got) != 1 || got[0] != "old.example.com" {
		t.Fatalf("initial DNS names = %v", got)
	}

	if _, err := GenCerts([]string{"old.example.com", "new.example.com"}, serverCert, serverKey, caKey, caCert, false); err != nil {
		t.Fatalf("regen server cert: %v", err)
	}
	if err := ReloadServerTLSCert(); err != nil {
		t.Fatalf("reload updated cert: %v", err)
	}
	names := parseNames()
	if len(names) != 2 || names[0] != "old.example.com" || names[1] != "new.example.com" {
		t.Fatalf("updated DNS names = %v, want old and new", names)
	}
}

func TestReloadServerTLSCertMissingFiles(t *testing.T) {
	previousCrt, previousKey := ServerCrtFile, ServerKeyFile
	ServerCrtFile = filepath.Join(t.TempDir(), "missing-cert.pem")
	ServerKeyFile = filepath.Join(t.TempDir(), "missing-key.pem")
	t.Cleanup(func() { ServerCrtFile, ServerKeyFile = previousCrt, previousKey })

	if err := ReloadServerTLSCert(); err == nil {
		t.Fatal("ReloadServerTLSCert with missing files should fail")
	}
	if _, err := os.Stat(ServerCrtFile); !os.IsNotExist(err) {
		t.Fatalf("missing cert unexpectedly exists: %v", err)
	}
}
