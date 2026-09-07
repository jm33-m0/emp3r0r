package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestGenCertsCAAndServer verifies GenCerts produces a usable CA cert/key pair
// and a server cert signed by that CA, with the host names embedded.
func TestGenCertsCAAndServer(t *testing.T) {
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca-cert.pem")
	caKey := filepath.Join(dir, "ca-key.pem")

	if _, err := GenCerts(nil, caCert, caKey, "", "", true); err != nil {
		t.Fatalf("GenCerts CA: %v", err)
	}
	if _, err := os.Stat(caCert); err != nil {
		t.Fatalf("CA cert not written: %v", err)
	}
	if _, err := os.Stat(caKey); err != nil {
		t.Fatalf("CA key not written: %v", err)
	}

	// Server cert signed by the CA, with DNS + IP SANs.
	serverCert := filepath.Join(dir, "server-cert.pem")
	serverKey := filepath.Join(dir, "server-key.pem")
	pubPEM, err := GenCerts([]string{"emp3r0r.test", "10.0.0.1"}, serverCert, serverKey, caKey, caCert, false)
	if err != nil {
		t.Fatalf("GenCerts server: %v", err)
	}
	if !strings.Contains(string(pubPEM), "PUBLIC KEY") {
		t.Fatalf("expected PEM-encoded public key output, got: %q", pubPEM)
	}

	// Server cert must be valid and contain the requested names.
	names := NamesInCert(serverCert)
	found := map[string]bool{}
	for _, n := range names {
		found[n] = true
	}
	if !found["emp3r0r.test"] || !found["10.0.0.1"] {
		t.Fatalf("NamesInCert = %v, want emp3r0r.test and 10.0.0.1", names)
	}

	// Parse helpers round-trip the written files.
	caCertParsed, err := ParseCertPemFile(caCert)
	if err != nil {
		t.Fatalf("ParseCertPemFile: %v", err)
	}
	if !caCertParsed.IsCA {
		t.Fatal("parsed CA cert should be a CA")
	}
	caKeyParsed, err := ParseKeyPemFile(caKey)
	if err != nil {
		t.Fatalf("ParseKeyPemFile: %v", err)
	}
	if !caKeyParsed.PublicKey.Equal(caCertParsed.PublicKey) {
		t.Fatal("CA key public key does not match CA cert public key")
	}

	// Server cert must chain to the CA.
	serverCertParsed, err := ParseCertPemFile(serverCert)
	if err != nil {
		t.Fatalf("ParseCertPemFile server: %v", err)
	}
	if err := serverCertParsed.CheckSignatureFrom(caCertParsed); err != nil {
		t.Fatalf("server cert not signed by CA: %v", err)
	}

	// Missing file error paths.
	if _, err := ParseCertPemFile(filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("expected error parsing missing cert file")
	}
	if _, err := ParseKeyPemFile(filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("expected error parsing missing key file")
	}
	if got := NamesInCert(filepath.Join(dir, "missing.pem")); len(got) != 0 {
		t.Fatalf("NamesInCert on missing file should be empty, got %v", got)
	}
}

// TestGetFingerprintAndPublicKeyToPEM verifies fingerprint computation and PEM
// key encoding round-trips.
func TestGetFingerprintAndPublicKeyToPEM(t *testing.T) {
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.pem")
	caKey := filepath.Join(dir, "ca-key.pem")
	if _, err := GenCerts(nil, caCert, caKey, "", "", true); err != nil {
		t.Fatalf("GenCerts: %v", err)
	}

	fp := GetFingerprint(caCert)
	if len(fp) != 64 { // hex-encoded sha256
		t.Fatalf("GetFingerprint returned %d chars, want 64: %q", len(fp), fp)
	}
	if GetFingerprint(filepath.Join(dir, "missing.pem")) != "" {
		t.Fatal("GetFingerprint on missing file should be empty")
	}

	key, err := ParseKeyPemFile(caKey)
	if err != nil {
		t.Fatalf("ParseKeyPemFile: %v", err)
	}
	pemBytes, err := PublicKeyToPEM(&key.PublicKey)
	if err != nil {
		t.Fatalf("PublicKeyToPEM: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("PublicKeyToPEM produced invalid PEM: %q", pemBytes)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key PEM: %v", err)
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok || !ecdsaPub.Equal(&key.PublicKey) {
		t.Fatal("PublicKeyToPEM round-trip mismatch")
	}

	if _, err := PublicKeyToPEM(nil); err == nil {
		t.Fatal("PublicKeyToPEM(nil) should error")
	}
}

// TestSSHKeyHelpers verifies GenerateSSHKeyPair produces a parseable ECDSA
// key pair whose SSH public key is derived correctly.
func TestSSHKeyHelpers(t *testing.T) {
	privPEM, pubPEM, err := GenerateSSHKeyPair()
	if err != nil {
		t.Fatalf("GenerateSSHKeyPair: %v", err)
	}
	if len(privPEM) == 0 || len(pubPEM) == 0 {
		t.Fatal("GenerateSSHKeyPair returned empty keys")
	}

	pub, err := SSHPublicKey(privPEM)
	if err != nil {
		t.Fatalf("SSHPublicKey: %v", err)
	}
	if pub.Type() != "ecdsa-sha2-nistp256" {
		t.Fatalf("SSHPublicKey type = %q, want ecdsa-sha2-nistp256", pub.Type())
	}

	// The OpenSSH public key re-parses from its own wire encoding.
	wire := ssh.MarshalAuthorizedKey(pub)
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(wire)
	if err != nil {
		t.Fatalf("re-parse ssh pubkey: %v", err)
	}
	if parsed.Type() != pub.Type() {
		t.Fatalf("round-tripped ssh key type = %q, want %q", parsed.Type(), pub.Type())
	}

	if _, err := SSHPublicKey([]byte("not-a-key")); err == nil {
		t.Fatal("SSHPublicKey on garbage should error")
	}
}

// TestSignJSONWithKey verifies SignJSONWithKey produces signatures verified by
// VerifySignatureWithPEM.
func TestSignJSONWithKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	pemBytes, err := PublicKeyToPEM(&key.PublicKey)
	if err != nil {
		t.Fatalf("PublicKeyToPEM: %v", err)
	}

	data := []byte(`{"hello":"world"}`)
	sig, err := SignJSONWithKey(key, data)
	if err != nil {
		t.Fatalf("SignJSONWithKey: %v", err)
	}
	ok, err := VerifySignatureWithPEM(pemBytes, data, sig)
	if err != nil || !ok {
		t.Fatalf("VerifySignatureWithPEM: ok=%v err=%v", ok, err)
	}
	if _, err := SignJSONWithKey(nil, data); err == nil {
		t.Fatal("SignJSONWithKey(nil key) should error")
	}
}
