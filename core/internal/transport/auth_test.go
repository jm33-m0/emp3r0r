package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
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

// TestCanonicalAuthStringDeterministicAndSorted verifies the canonical auth
// string is stable: capabilities sorted, fields joined in a fixed order, and
// independent of map/argument ordering.
func TestCanonicalAuthStringDeterministicAndSorted(t *testing.T) {
	a := CanonicalAuthString("agent-uuid", 1234567890, "nonce-x", []string{"exec", "shell", "get"})
	b := CanonicalAuthString("agent-uuid", 1234567890, "nonce-x", []string{"shell", "get", "exec"})
	if a != b {
		t.Fatalf("canonical string not order-independent:\n%q\n%q", a, b)
	}
	want := "agent-uuid\n1234567890\nnonce-x\nexec,get,shell"
	if a != want {
		t.Fatalf("canonical string = %q, want %q", a, want)
	}

	// Input slice must not be mutated by canonicalization.
	caps := []string{"z", "a"}
	_ = CanonicalAuthString("u", 1, "n", caps)
	if caps[0] != "z" || caps[1] != "a" {
		t.Fatalf("CanonicalAuthString mutated caller slice: %v", caps)
	}

	// Nil / empty capabilities must canonicalize the same as no caps.
	empty := CanonicalAuthString("u", 1, "n", nil)
	alsoEmpty := CanonicalAuthString("u", 1, "n", []string{})
	if empty != alsoEmpty {
		t.Fatalf("nil vs empty capabilities differ: %q vs %q", empty, alsoEmpty)
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
			IdentityToken: base64.URLEncoding.EncodeToString(sig),
			Nonce:         "nonce",
			Timestamp:     time.Now().Unix(),
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
	t.Run("empty agent uuid", func(t *testing.T) {
		a := mk(func(m *def.MsgAuth) { m.AgentUUID = "" })
		if err := VerifyMsgAuth(a); err == nil {
			t.Fatal("expected error for empty AgentUUID")
		}
	})
	t.Run("missing identity token", func(t *testing.T) {
		a := mk(func(m *def.MsgAuth) { m.IdentityToken = "" })
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
	t.Run("undecodable identity token", func(t *testing.T) {
		a := mk(func(m *def.MsgAuth) { m.IdentityToken = "!!!not-base64!!!" })
		if err := VerifyMsgAuth(a); err == nil {
			t.Fatal("expected error for undecodable identity token")
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
		IdentityToken: base64.URLEncoding.EncodeToString(sig),
		Nonce:         "nonce",
		Timestamp:     time.Now().Unix(),
	}
	if err := VerifyMsgAuth(auth); err != nil {
		t.Fatalf("valid MsgAuth rejected: %v", err)
	}
}

// TestCanonicalOperatorStreamClaimString verifies field order and nil safety.
func TestCanonicalOperatorStreamClaimString(t *testing.T) {
	if got := CanonicalOperatorStreamClaimString(nil); got != "" {
		t.Fatalf("nil claim should canonicalize to empty string, got %q", got)
	}
	claim := &def.OperatorStreamClaim{
		OperatorSession: "sess",
		StreamID:        "stream-1",
		Capability:      "shell",
		IssuedAt:        100,
		ExpiresAt:       200,
		Nonce:           "n1",
	}
	want := "sess\nstream-1\nshell\n100\n200\nn1"
	if got := CanonicalOperatorStreamClaimString(claim); got != want {
		t.Fatalf("claim canonical string = %q, want %q", got, want)
	}
}

// TestVerifyOperatorStreamClaim exercises the full sign/verify cycle with a
// real operator ECDSA key, plus every rejection branch.
func TestVerifyOperatorStreamClaim(t *testing.T) {
	opKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate operator key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&opKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	opPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	now := time.Now().Unix()
	mk := func(mut func(*def.OperatorStreamClaim)) *def.OperatorStreamClaim {
		c := &def.OperatorStreamClaim{
			OperatorSession: "sess-1",
			StreamID:        "stream-1",
			Capability:      "shell",
			IssuedAt:        now - 5,
			ExpiresAt:       now + 30,
			Nonce:           "nonce-abc",
		}
		mut(c)
		canonical := CanonicalOperatorStreamClaimString(c)
		sig, err := SignECDSA([]byte(canonical), opKey)
		if err != nil {
			t.Fatalf("sign claim: %v", err)
		}
		c.Signature = sig
		return c
	}

	t.Run("valid claim", func(t *testing.T) {
		c := mk(func(*def.OperatorStreamClaim) {})
		if err := VerifyOperatorStreamClaim(c, "sess-1", "stream-1", "shell", opPubPEM); err != nil {
			t.Fatalf("valid claim rejected: %v", err)
		}
	})
	t.Run("nil claim", func(t *testing.T) {
		if err := VerifyOperatorStreamClaim(nil, "s", "s", "c", opPubPEM); err == nil {
			t.Fatal("expected error for nil claim")
		}
	})
	t.Run("empty required field", func(t *testing.T) {
		c := mk(func(cl *def.OperatorStreamClaim) { cl.Nonce = "" })
		if err := VerifyOperatorStreamClaim(c, "sess-1", "stream-1", "shell", opPubPEM); err == nil {
			t.Fatal("expected error for empty nonce")
		}
	})
	t.Run("missing signature", func(t *testing.T) {
		c := mk(func(*def.OperatorStreamClaim) {})
		c.Signature = nil
		if err := VerifyOperatorStreamClaim(c, "sess-1", "stream-1", "shell", opPubPEM); err == nil {
			t.Fatal("expected error for missing signature")
		}
	})
	t.Run("invalid expected context", func(t *testing.T) {
		c := mk(func(*def.OperatorStreamClaim) {})
		if err := VerifyOperatorStreamClaim(c, "", "stream-1", "shell", opPubPEM); err == nil {
			t.Fatal("expected error for empty expected session")
		}
	})
	t.Run("session mismatch", func(t *testing.T) {
		c := mk(func(*def.OperatorStreamClaim) {})
		if err := VerifyOperatorStreamClaim(c, "other-sess", "stream-1", "shell", opPubPEM); err == nil {
			t.Fatal("expected error for session mismatch")
		}
	})
	t.Run("stream id mismatch", func(t *testing.T) {
		c := mk(func(*def.OperatorStreamClaim) {})
		if err := VerifyOperatorStreamClaim(c, "sess-1", "other-stream", "shell", opPubPEM); err == nil {
			t.Fatal("expected error for stream id mismatch")
		}
	})
	t.Run("capability mismatch", func(t *testing.T) {
		c := mk(func(*def.OperatorStreamClaim) {})
		if err := VerifyOperatorStreamClaim(c, "sess-1", "stream-1", "other-cap", opPubPEM); err == nil {
			t.Fatal("expected error for capability mismatch")
		}
	})
	t.Run("invalid timestamps", func(t *testing.T) {
		c := mk(func(cl *def.OperatorStreamClaim) { cl.ExpiresAt = cl.IssuedAt })
		if err := VerifyOperatorStreamClaim(c, "sess-1", "stream-1", "shell", opPubPEM); err == nil {
			t.Fatal("expected error for expires<=issued")
		}
	})
	t.Run("ttl exceeds limit", func(t *testing.T) {
		c := mk(func(cl *def.OperatorStreamClaim) { cl.ExpiresAt = now + OperatorClaimMaxTTLSeconds + 1000 })
		if err := VerifyOperatorStreamClaim(c, "sess-1", "stream-1", "shell", opPubPEM); err == nil {
			t.Fatal("expected error for TTL over limit")
		}
	})
	t.Run("outside replay window", func(t *testing.T) {
		c := mk(func(cl *def.OperatorStreamClaim) {
			cl.IssuedAt = now - ReplayWindowSeconds - 1000
			cl.ExpiresAt = now - ReplayWindowSeconds - 900
		})
		if err := VerifyOperatorStreamClaim(c, "sess-1", "stream-1", "shell", opPubPEM); err == nil {
			t.Fatal("expected error for claim outside replay window")
		}
	})
	t.Run("tampered claim", func(t *testing.T) {
		c := mk(func(*def.OperatorStreamClaim) {})
		// Tamper with a signed field; signature no longer matches canonical.
		c.Nonce = "tampered"
		err := VerifyOperatorStreamClaim(c, "sess-1", "stream-1", "shell", opPubPEM)
		if err == nil {
			t.Fatal("expected signature verification failure for tampered claim")
		}
		if !strings.Contains(err.Error(), "verification") {
			t.Fatalf("expected verification error wording, got: %v", err)
		}
	})
	t.Run("signature from another key", func(t *testing.T) {
		c := mk(func(*def.OperatorStreamClaim) {})
		otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate other key: %v", err)
		}
		canonical := CanonicalOperatorStreamClaimString(c)
		sig, err := SignECDSA([]byte(canonical), otherKey)
		if err != nil {
			t.Fatalf("sign with other key: %v", err)
		}
		c.Signature = sig
		if err := VerifyOperatorStreamClaim(c, "sess-1", "stream-1", "shell", opPubPEM); err == nil {
			t.Fatal("expected failure when claim signed by a different key")
		}
	})
	t.Run("garbage public key pem", func(t *testing.T) {
		c := mk(func(*def.OperatorStreamClaim) {})
		if err := VerifyOperatorStreamClaim(c, "sess-1", "stream-1", "shell", []byte("not-pem")); err == nil {
			t.Fatal("expected error for invalid operator public key")
		}
	})
}
