package server

import (
	"bytes"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

func setupCertTestFiles(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca-cert.pem")
	caKey := filepath.Join(dir, "ca-key.pem")
	serverCert := filepath.Join(dir, "server-cert.pem")
	serverKey := filepath.Join(dir, "server-key.pem")

	previousCrt, previousKey := transport.ServerCrtFile, transport.ServerKeyFile
	previousCACrt, previousCAKey := transport.CaCrtFile, transport.CaKeyFile
	transport.ServerCrtFile, transport.ServerKeyFile = serverCert, serverKey
	transport.CaCrtFile, transport.CaKeyFile = caCert, caKey
	t.Cleanup(func() {
		transport.ServerCrtFile, transport.ServerKeyFile = previousCrt, previousKey
		transport.CaCrtFile, transport.CaKeyFile = previousCACrt, previousCAKey
	})

	if _, err := transport.GenCerts(nil, caCert, caKey, "", "", true); err != nil {
		t.Fatalf("GenCerts CA: %v", err)
	}
	if _, err := transport.GenCerts([]string{"old.example.com"}, serverCert, serverKey, caKey, caCert, false); err != nil {
		t.Fatalf("GenCerts server: %v", err)
	}
	if err := transport.ReloadServerTLSCert(); err != nil {
		t.Fatalf("ReloadServerTLSCert: %v", err)
	}
}

func TestNormalizeCertHosts(t *testing.T) {
	got := normalizeCertHosts([]string{" New.Example.COM ", "new.example.com", "bad host", "127.0.0.1"})
	want := []string{"new.example.com", "127.0.0.1"}
	if !slices.Equal(got, want) {
		t.Fatalf("normalizeCertHosts = %v, want %v", got, want)
	}
}

func TestHandleEnsureCertUpdatesAndReloads(t *testing.T) {
	previousWS := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = previousWS })
	setupCertTestFiles(t)

	body, err := cbor.Marshal(def.EnsureCertRequest{Hosts: []string{"new.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/operator/ensure_cert", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("operator_session", "cert-test-operator")
	rec := httptest.NewRecorder()

	handleEnsureCert(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("handleEnsureCert = %d: %s", rec.Code, rec.Body.String())
	}

	names := transport.NamesInCert(transport.ServerCrtFile)
	for _, want := range []string{"old.example.com", "new.example.com"} {
		if !slices.Contains(names, want) {
			t.Fatalf("updated cert names = %v, missing %q", names, want)
		}
	}

	cert, err := transport.GetServerTLSCert(nil)
	if err != nil {
		t.Fatalf("GetServerTLSCert: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if !slices.Contains(leaf.DNSNames, "new.example.com") {
		t.Fatalf("loaded TLS leaf names = %v, missing new.example.com", leaf.DNSNames)
	}
}

func TestHandleEnsureCertRejectsInvalidHost(t *testing.T) {
	previousWS := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	t.Cleanup(func() { live.EmpWorkSpace = previousWS })
	setupCertTestFiles(t)

	body, err := cbor.Marshal(def.EnsureCertRequest{Hosts: []string{"bad host"}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/operator/ensure_cert", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("operator_session", "cert-test-operator")
	rec := httptest.NewRecorder()

	handleEnsureCert(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid host status = %d, want 400", rec.Code)
	}
}
