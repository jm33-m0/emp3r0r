package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// genCA returns a fresh ECDSA CA key/cert pair, used to sign and verify the
// CA-level identity tokens carried by MsgAuth.
func genCA(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	return caKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestCanonicalAuthString pins the canonical auth string for a single route.
func TestCanonicalAuthString(t *testing.T) {
	got := CanonicalAuthString("agent-uuid", 1234567890, "nonce-x", "c2-msg")
	want := "agent-uuid\n1234567890\nnonce-x\nc2-msg"
	if got != want {
		t.Fatalf("canonical string = %q, want %q", got, want)
	}

	empty := CanonicalAuthString("u", 1, "n", "")
	if empty != "u\n1\nn\n" {
		t.Fatalf("empty route canonical string = %q", empty)
	}
}

// TestVerifyMsgAuthRejectsMalformed verifies every structural validation
// rejects before any crypto work happens.
func TestVerifyMsgAuthRejectsMalformed(t *testing.T) {
	caKey, caPEM := genCA(t)
	orig := GetCACrtPEM()
	SetCACrtPEM(caPEM)
	defer SetCACrtPEM(orig)

	mk := func(mut func(*def.MsgAuth)) *def.MsgAuth {
		// Valid CA identity token over the agent UUID.
		sig, err := SignECDSA([]byte("agent-1"), caKey)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		a := &def.MsgAuth{
			Type:          def.MsgAuthType,
			AgentUUID:     "agent-1",
			IdentityToken: sig,
			Nonce:         "nonce",
			Timestamp:     time.Now().Unix(),
			Route:         "c2-msg",
		}
		mut(a)
		return a
	}

	t.Run("nil", func(t *testing.T) {
		if err := VerifyMsgAuth(nil); err == nil {
			t.Fatal("expected error for nil MsgAuth")
		}
	})
	t.Run("wrong type", func(t *testing.T) {
		a := mk(func(m *def.MsgAuth) { m.Type = "nope" })
		if err := VerifyMsgAuth(a); err == nil {
			t.Fatal("expected error for wrong type")
		}
	})
	t.Run("missing route", func(t *testing.T) {
		a := mk(func(m *def.MsgAuth) { m.Route = "" })
		if err := VerifyMsgAuth(a); err == nil {
			t.Fatal("expected error for missing route")
		}
	})
	t.Run("empty agent uuid", func(t *testing.T) {
		a := mk(func(m *def.MsgAuth) { m.AgentUUID = "" })
		if err := VerifyMsgAuth(a); err == nil {
			t.Fatal("expected error for empty AgentUUID")
		}
	})
	t.Run("missing identity token", func(t *testing.T) {
		a := mk(func(m *def.MsgAuth) { m.IdentityToken = nil })
		if err := VerifyMsgAuth(a); err == nil {
			t.Fatal("expected error for missing identity token")
		}
	})
	t.Run("missing nonce", func(t *testing.T) {
		a := mk(func(m *def.MsgAuth) { m.Nonce = "" })
		if err := VerifyMsgAuth(a); err == nil {
			t.Fatal("expected error for missing nonce")
		}
	})
	t.Run("zero timestamp", func(t *testing.T) {
		a := mk(func(m *def.MsgAuth) { m.Timestamp = 0 })
		if err := VerifyMsgAuth(a); err == nil {
			t.Fatal("expected error for zero timestamp")
		}
	})
	t.Run("future outside replay window", func(t *testing.T) {
		a := mk(func(m *def.MsgAuth) { m.Timestamp = time.Now().Unix() + 3600 })
		if err := VerifyMsgAuth(a); err == nil {
			t.Fatal("expected error for future timestamp")
		}
	})
	t.Run("past outside replay window", func(t *testing.T) {
		a := mk(func(m *def.MsgAuth) { m.Timestamp = time.Now().Unix() - 3600 })
		if err := VerifyMsgAuth(a); err == nil {
			t.Fatal("expected error for stale timestamp")
		}
	})
	t.Run("invalid identity token", func(t *testing.T) {
		a := mk(func(m *def.MsgAuth) { m.IdentityToken = []byte("invalid") })
		if err := VerifyMsgAuth(a); err == nil {
			t.Fatal("expected error for invalid identity token")
		}
	})
	t.Run("signature over different agent", func(t *testing.T) {
		// Signed for agent-1 but claims agent-2: CA token must not verify.
		a := mk(func(m *def.MsgAuth) { m.AgentUUID = "agent-2" })
		if err := VerifyMsgAuth(a); err == nil {
			t.Fatal("expected error when identity token does not match AgentUUID")
		}
	})
}

// TestVerifyMsgAuthAcceptsValidToken is the positive path: a CA-signed token
// for the right agent UUID passes.
func TestVerifyMsgAuthAcceptsValidToken(t *testing.T) {
	caKey, caPEM := genCA(t)
	orig := GetCACrtPEM()
	SetCACrtPEM(caPEM)
	defer SetCACrtPEM(orig)

	sig, err := SignECDSA([]byte("agent-1"), caKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	auth := &def.MsgAuth{
		Type:          def.MsgAuthType,
		AgentUUID:     "agent-1",
		IdentityToken: sig,
		Nonce:         "nonce",
		Timestamp:     time.Now().Unix(),
		Route:         "c2-msg",
	}
	if err := VerifyMsgAuth(auth); err != nil {
		t.Fatalf("valid MsgAuth rejected: %v", err)
	}
}
