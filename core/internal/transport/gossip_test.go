package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/hashicorp/memberlist"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// ─── helpers ────────────────────────────────────────────────────────────────

// setupTestCA generates an ephemeral ECDSA CA in-memory and wires it into
// the transport package globals (CACrtPEM, CaKeyFile).
// Returns a cleanup function that restores the originals.
func setupTestCA(t *testing.T) (caKey *ecdsa.PrivateKey, cleanup func()) {
	t.Helper()

	// Generate CA key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	// Self-signed CA certificate
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// PEM-encode the private key
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Write the key to a temp file (SignWithCAKey reads from CaKeyFile)
	tmpKey, err := os.CreateTemp("", "test-ca-key-*.pem")
	if err != nil {
		t.Fatalf("create temp key file: %v", err)
	}
	if _, err = tmpKey.Write(keyPEM); err != nil {
		t.Fatalf("write temp key: %v", err)
	}
	tmpKey.Close()

	// Swap globals
	origCACrtPEM := GetCACrtPEM()
	origCaKeyFile := CaKeyFile

	SetCACrtPEM(certPEM)
	CaKeyFile = tmpKey.Name()

	cleanup = func() {
		SetCACrtPEM(origCACrtPEM)
		CaKeyFile = origCaKeyFile
		os.Remove(tmpKey.Name())
	}
	return key, cleanup
}

// signTokenDirect signs an AgentToken's payload using the supplied key, so we
// can craft tokens with known-good or known-bad signatures without going through
// the file-based SignWithCAKey helper.
func signTokenDirect(t *testing.T, tok *def.AgentToken, key *ecdsa.PrivateKey) {
	t.Helper()
	payload := fmt.Sprintf("%s%s%s%d", tok.AgentID, tok.IP, tok.Capability, tok.ExpiresAt)
	hash := sha256.Sum256([]byte(payload))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	var sig struct{ R, S *big.Int }
	sig.R, sig.S = r, s
	tok.Signature, err = asn1.Marshal(sig)
	if err != nil {
		t.Fatalf("marshal signature: %v", err)
	}
}

// ─── AgentToken struct ───────────────────────────────────────────────────────

func TestAgentTokenConstants(t *testing.T) {
	if def.TagAgentToken == "" {
		t.Error("TagAgentToken must not be empty")
	}
	if def.CapabilityProxy == "" {
		t.Error("CapabilityProxy must not be empty")
	}
}

func TestAgentTokenCBORRoundTrip(t *testing.T) {
	original := &def.AgentToken{
		AgentID:    "agent-123",
		IP:         "10.0.0.1",
		Capability: def.CapabilityProxy,
		ExpiresAt:  time.Now().Add(24 * time.Hour).Unix(),
		Signature:  []byte{0xde, 0xad, 0xbe, 0xef},
	}

	data, err := cbor.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded def.AgentToken
	if err := cbor.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.AgentID != original.AgentID ||
		decoded.IP != original.IP ||
		decoded.Capability != original.Capability ||
		decoded.ExpiresAt != original.ExpiresAt {
		t.Errorf("round-trip mismatch: got %+v, want %+v", decoded, original)
	}
}

// ─── Signing round-trip ──────────────────────────────────────────────────────

func TestSignWithCAKey_VerifySignatureWithCA_RoundTrip(t *testing.T) {
	_, cleanup := setupTestCA(t)
	defer cleanup()

	payload := []byte("test-agent-idtest-ip192.168.1.1proxy1700000000")
	hash := sha256.Sum256(payload)

	sig, err := SignWithCAKey(hash[:])
	if err != nil {
		t.Fatalf("SignWithCAKey: %v", err)
	}

	valid, err := VerifySignatureWithCA(hash[:], sig)
	if err != nil {
		t.Fatalf("VerifySignatureWithCA: %v", err)
	}
	if !valid {
		t.Error("expected valid signature, got invalid")
	}
}

func TestVerifySignatureWithCA_TamperedData(t *testing.T) {
	_, cleanup := setupTestCA(t)
	defer cleanup()

	original := []byte("correct-payload")
	hash := sha256.Sum256(original)

	sig, err := SignWithCAKey(hash[:])
	if err != nil {
		t.Fatalf("SignWithCAKey: %v", err)
	}

	// Tamper: change one byte in the hash
	tampered := make([]byte, len(hash))
	copy(tampered, hash[:])
	tampered[0] ^= 0xff

	valid, err := VerifySignatureWithCA(tampered, sig)
	if err != nil {
		t.Logf("VerifySignatureWithCA (tampered) error (acceptable): %v", err)
	}
	if valid {
		t.Error("expected invalid signature for tampered data, but got valid")
	}
}

func TestVerifySignatureWithCA_WrongKey(t *testing.T) {
	_, cleanup := setupTestCA(t)
	defer cleanup()

	// Generate a different key to forge a signature
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}

	payload := []byte("some-payload")
	hash := sha256.Sum256(payload)

	r, s, err := ecdsa.Sign(rand.Reader, otherKey, hash[:])
	if err != nil {
		t.Fatalf("sign with other key: %v", err)
	}
	var asn1Sig struct{ R, S *big.Int }
	asn1Sig.R, asn1Sig.S = r, s
	sig, err := asn1.Marshal(asn1Sig)
	if err != nil {
		t.Fatalf("marshal sig: %v", err)
	}

	valid, _ := VerifySignatureWithCA(hash[:], sig)
	if valid {
		t.Error("expected signature by wrong key to fail verification")
	}
}

// ─── AgentToken full signing round-trip ─────────────────────────────────────

func TestAgentTokenSignAndVerify(t *testing.T) {
	_, cleanup := setupTestCA(t)
	defer cleanup()

	tok := &def.AgentToken{
		AgentID:    "uuid-abc",
		IP:         "192.168.1.50",
		Capability: def.CapabilityProxy,
		ExpiresAt:  time.Now().Add(24 * time.Hour).Unix(),
	}

	// Sign via SignWithCAKey directly (no pre-hash; SignWithCAKey hashes internally).
	payload := fmt.Sprintf("%s%s%s%d", tok.AgentID, tok.IP, tok.Capability, tok.ExpiresAt)
	sig, err := SignWithCAKey([]byte(payload))
	if err != nil {
		t.Fatalf("SignWithCAKey: %v", err)
	}
	tok.Signature = sig

	// Verify using the same raw payload — VerifySignatureWithCA hashes internally.
	valid, err := VerifySignatureWithCA([]byte(payload), tok.Signature)
	if err != nil {
		t.Fatalf("VerifySignatureWithCA: %v", err)
	}
	if !valid {
		t.Error("AgentToken signature should be valid")
	}
}

// ─── GossipDelegate ─────────────────────────────────────────────────────────

func TestGossipDelegate_NodeMeta_NilToken(t *testing.T) {
	d := &GossipDelegate{GetMeta: func() *def.MeshNodeMeta { return nil }}
	meta := d.NodeMeta(512)
	if len(meta) != 0 {
		t.Errorf("expected empty NodeMeta for nil token, got %d bytes", len(meta))
	}
}

func TestGossipDelegate_NodeMeta_ValidToken(t *testing.T) {
	tok := &def.AgentToken{
		AgentID:    "agent-xyz",
		IP:         "10.1.2.3",
		Capability: def.CapabilityProxy,
		ExpiresAt:  time.Now().Add(time.Hour).Unix(),
		Signature:  []byte{1, 2, 3, 4},
	}
	d := &GossipDelegate{GetMeta: func() *def.MeshNodeMeta { return &def.MeshNodeMeta{Token: tok, Distance: 0} }}
	meta := d.NodeMeta(512)
	if len(meta) == 0 {
		t.Fatal("expected non-empty NodeMeta for valid token")
	}

	// Deserialise and check round-trip
	var decoded def.MeshNodeMeta
	if err := cbor.Unmarshal(meta, &decoded); err != nil {
		t.Fatalf("unmarshal NodeMeta: %v", err)
	}
	if decoded.Token == nil || decoded.Token.AgentID != tok.AgentID || decoded.Token.Capability != tok.Capability {
		t.Errorf("NodeMeta round-trip mismatch: got %+v, want %+v", decoded.Token, tok)
	}
}

func TestGossipDelegate_NodeMeta_ExceedsLimit(t *testing.T) {
	tok := &def.AgentToken{
		AgentID:    "agent-xyz",
		IP:         "10.1.2.3",
		Capability: def.CapabilityProxy,
		ExpiresAt:  time.Now().Add(time.Hour).Unix(),
		Signature:  make([]byte, 200), // large
	}
	d := &GossipDelegate{GetMeta: func() *def.MeshNodeMeta { return &def.MeshNodeMeta{Token: tok, Distance: 0} }}
	// Tiny limit to force truncation path
	meta := d.NodeMeta(4)
	if len(meta) != 0 {
		t.Error("expected empty NodeMeta when token exceeds limit")
	}
}

func TestGossipDelegate_LocalState(t *testing.T) {
	tok := &def.AgentToken{AgentID: "x", Capability: def.CapabilityProxy, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	d := &GossipDelegate{GetMeta: func() *def.MeshNodeMeta { return &def.MeshNodeMeta{Token: tok, Distance: 0} }}
	// LocalState calls NodeMeta(512); just ensure no panic and non-empty result
	state := d.LocalState(false)
	if len(state) == 0 {
		t.Error("LocalState should return non-empty bytes for valid token")
	}
}

// ─── GetAuthorizedPeers validation logic ────────────────────────────────────
// We test the token-validation path independently of a live memberlist by
// unit-testing the three rejection conditions (wrong capability, expired,
// bad signature) and then validating a correct token passes all checks.
//
// Because GetAuthorizedPeers iterates memberlist.Members() and real memberlist
// Members wraps internal node structs with IP addresses assigned by the OS, we
// test the filtering conditions through a purpose-built helper that mirrors
// the exact same logic as GetAuthorizedPeers but accepts a plain []def.AgentToken
// slice, so we can unit-test it without network access.

func authorizedTokens(tokens []def.AgentToken, capability string) []def.AgentToken {
	var out []def.AgentToken
	for _, tok := range tokens {
		if tok.Capability != capability {
			continue
		}
		if time.Now().Unix() > tok.ExpiresAt {
			continue
		}
		payload := fmt.Sprintf("%s%s%s%d", tok.AgentID, tok.IP, tok.Capability, tok.ExpiresAt)
		valid, err := VerifySignatureWithCA([]byte(payload), tok.Signature)
		if err != nil || !valid {
			continue
		}
		out = append(out, tok)
	}
	return out
}

func TestGetAuthorizedPeers_Logic(t *testing.T) {
	caKey, cleanup := setupTestCA(t)
	defer cleanup()

	now := time.Now()

	// Helper to build token
	makeToken := func(cap string, expiresAt int64, tamper bool) def.AgentToken {
		tok := def.AgentToken{
			AgentID:    "agent-test",
			IP:         "10.0.0.5",
			Capability: cap,
			ExpiresAt:  expiresAt,
		}
		signTokenDirect(t, &tok, caKey)
		if tamper {
			tok.AgentID = "attacker" // invalidates signature
		}
		return tok
	}

	validProxy := makeToken(def.CapabilityProxy, now.Add(time.Hour).Unix(), false)
	expiredProxy := makeToken(def.CapabilityProxy, now.Add(-time.Hour).Unix(), false)
	wrongCap := makeToken("relay", now.Add(time.Hour).Unix(), false)
	tamperedProxy := makeToken(def.CapabilityProxy, now.Add(time.Hour).Unix(), true)

	tests := []struct {
		name   string
		tokens []def.AgentToken
		cap    string
		want   int // expected count of authorized
	}{
		{"valid proxy token", []def.AgentToken{validProxy}, def.CapabilityProxy, 1},
		{"expired token rejected", []def.AgentToken{expiredProxy}, def.CapabilityProxy, 0},
		{"wrong capability rejected", []def.AgentToken{wrongCap}, def.CapabilityProxy, 0},
		{"tampered signature rejected", []def.AgentToken{tamperedProxy}, def.CapabilityProxy, 0},
		{"mixed: only valid passes", []def.AgentToken{validProxy, expiredProxy, wrongCap, tamperedProxy}, def.CapabilityProxy, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := authorizedTokens(tt.tokens, tt.cap)
			if len(got) != tt.want {
				t.Errorf("got %d authorized, want %d", len(got), tt.want)
			}
		})
	}
}

// ─── StartGossip integration (single node, no peers) ────────────────────────

// TestStartGossip_BootstrapRetry verifies that if a node becomes isolated,
// it eventually rediscovers its bootstrap peers via the periodic join loop.
func TestStartGossip_BootstrapRetry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	// Make the gossip healing loop deterministic for CI: production uses randomized
	// 5-60s sleeps, which can exceed this test's rediscovery window on slower runners.
	origTakeASnap := util.TakeASnap
	util.TakeASnap = func(forceSleep bool) {
		time.Sleep(200 * time.Millisecond)
	}
	defer func() { util.TakeASnap = origTakeASnap }()

	// Find a free port for Node A (the seed)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	portA := l.Addr().(*net.TCPAddr).Port
	l.Close()

	// 1. Start Node A
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origPW := def.AESPassword
	def.AESPassword = make([]byte, 16)
	rand.Read(def.AESPassword)
	defer func() { def.AESPassword = origPW }()

	tokA := &def.AgentToken{AgentID: "node-a", Capability: def.CapabilityProxy, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	listA, err := StartGossip(ctx, "bootstrap-retry-node-a", nil, portA, func() *def.MeshNodeMeta {
		return &def.MeshNodeMeta{Token: tokA, Distance: 0}
	})
	if err != nil {
		t.Fatalf("Start Node A: %v", err)
	}

	// 2. Start Node B with Node A as bootstrap
	tokB := &def.AgentToken{AgentID: "node-b", Capability: def.CapabilityProxy, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	bootstrap := []byte(fmt.Sprintf("127.0.0.1:%d", portA))
	// We need a different port for Node B
	lB, _ := net.Listen("tcp", "127.0.0.1:0")
	portB := lB.Addr().(*net.TCPAddr).Port
	lB.Close()

	listB, err := StartGossip(ctx, "node-b", []string{string(bootstrap)}, portB, func() *def.MeshNodeMeta {
		return &def.MeshNodeMeta{Token: tokB, Distance: 1}
	})
	if err != nil {
		t.Fatalf("Start Node B: %v", err)
	}

	// Verify they see each other
	waitForPeers := func(list *memberlist.Memberlist, count int, timeout time.Duration) {
		start := time.Now()
		for time.Since(start) < timeout {
			if len(list.Members()) >= count {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatalf("timeout waiting for %d peers in %v (got %d)", count, timeout, len(list.Members()))
	}
	waitForPeers(listB, 2, 5*time.Second)
	t.Log("Nodes A and B are connected")

	// 3. Kill Node A
	listA.Shutdown()
	t.Log("Node A shut down")

	// Wait for Node B to detect death (memberlist detects this via gossip/probes)
	// Default memberlist settings might take a while, but we can just wait until alive count < 2
	start := time.Now()
	for {
		aliveNodes := 0
		for _, m := range listB.Members() {
			if m.State == memberlist.StateAlive {
				aliveNodes++
			}
		}
		if aliveNodes < 2 {
			break
		}
		if time.Since(start) > 60*time.Second {
			t.Fatal("timeout waiting for Node B to detect Node A's death")
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Log("Node B detected Node A's death")

	// 4. Start Node A again (same port)
	listA2, err := StartGossip(ctx, "node-a-restart", nil, portA, func() *def.MeshNodeMeta {
		return &def.MeshNodeMeta{Token: tokA, Distance: 0}
	})
	if err != nil {
		t.Fatalf("Restart Node A: %v", err)
	}
	defer listA2.Shutdown()
	t.Log("Node A restarted")

	// 5. Node B should eventually rediscover Node A via the periodic join loop.
	// Since we set the ticker to 30s in gossip.go, we should wait at least that long.
	// In a real test we might want to override the interval, but let's try with a long timeout first.
	t.Log("Waiting for Node B to rediscover Node A (deterministic retry interval)...")
	waitForPeers(listB, 2, 75*time.Second)
	t.Log("Node B successfully rediscovered Node A via bootstrap retry")
}

func TestStartGossip_SingleNode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	// Find a free port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	tok := &def.AgentToken{
		AgentID:    "local",
		Capability: def.CapabilityProxy,
		ExpiresAt:  time.Now().Add(time.Hour).Unix(),
	}

	// We need AESPassword to be a valid key length; DefaultWANConfig requires 16/24/32 bytes.
	origPW := def.AESPassword
	def.AESPassword = make([]byte, 16)
	rand.Read(def.AESPassword)
	defer func() { def.AESPassword = origPW }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	list, err := StartGossip(ctx, "single-node", nil, port, func() *def.MeshNodeMeta {
		return &def.MeshNodeMeta{Token: tok, Distance: 0}
	})
	if err != nil {
		t.Fatalf("StartGossip: %v", err)
	}
	defer list.Shutdown()

	if len(list.Members()) < 1 {
		t.Error("expected at least 1 member (self) in gossip list")
	}
	t.Logf("Gossip list has %d member(s)", len(list.Members()))
}

// TestStartGossip_ContextCancel verifies that a memberlist shuts down cleanly.
func TestStartGossip_ContextCancel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	origPW := def.AESPassword
	def.AESPassword = make([]byte, 16)
	rand.Read(def.AESPassword)
	defer func() { def.AESPassword = origPW }()

	config := memberlist.DefaultLocalConfig()
	config.Name = "context-cancel-node"
	config.BindPort = port
	config.AdvertisePort = port
	config.Logger = nil
	config.LogOutput = nil
	list, err := memberlist.Create(config)
	if err != nil {
		t.Fatalf("memberlist.Create: %v", err)
	}

	if err := list.Shutdown(); err != nil {
		t.Errorf("Shutdown error: %v", err)
	}
}
