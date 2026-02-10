package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestPerformECDH(t *testing.T) {
	// Generate two key pairs
	privKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key 1: %v", err)
	}

	privKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key 2: %v", err)
	}

	// Perform ECDH from both sides
	secret1, err := PerformECDH(privKey1, &privKey2.PublicKey)
	if err != nil {
		t.Fatalf("ECDH from side 1 failed: %v", err)
	}

	secret2, err := PerformECDH(privKey2, &privKey1.PublicKey)
	if err != nil {
		t.Fatalf("ECDH from side 2 failed: %v", err)
	}

	// Verify both sides computed the same shared secret
	if len(secret1) != len(secret2) {
		t.Fatalf("Shared secrets have different lengths: %d vs %d", len(secret1), len(secret2))
	}

	for i := range secret1 {
		if secret1[i] != secret2[i] {
			t.Fatal("Shared secrets do not match")
		}
	}

	// Verify secret is the right length (32 bytes for P256)
	if len(secret1) != 32 {
		t.Errorf("Expected 32-byte shared secret, got %d bytes", len(secret1))
	}
}

func TestPerformECDH_NilKeys(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Test with nil private key
	_, err := PerformECDH(nil, &privKey.PublicKey)
	if err == nil {
		t.Error("Expected error with nil private key")
	}

	// Test with nil public key
	_, err = PerformECDH(privKey, nil)
	if err == nil {
		t.Error("Expected error with nil public key")
	}
}

func TestDeriveSessionKey(t *testing.T) {
	// Generate a shared secret
	sharedSecret := make([]byte, 32)
	_, err := rand.Read(sharedSecret)
	if err != nil {
		t.Fatalf("Failed to generate shared secret: %v", err)
	}

	// Derive session key
	sessionKey, err := DeriveSessionKey(sharedSecret, "test-agent-uuid")
	if err != nil {
		t.Fatalf("DeriveSessionKey failed: %v", err)
	}

	// Verify session key is 32 bytes (AES-256)
	if len(sessionKey) != 32 {
		t.Errorf("Expected 32-byte session key, got %d bytes", len(sessionKey))
	}

	// Verify determinism - same input should produce same output
	sessionKey2, err := DeriveSessionKey(sharedSecret, "test-agent-uuid")
	if err != nil {
		t.Fatalf("Second DeriveSessionKey failed: %v", err)
	}

	for i := range sessionKey {
		if sessionKey[i] != sessionKey2[i] {
			t.Fatal("Session key derivation is not deterministic")
		}
	}
}

func TestGenerateEphemeralKeyPair(t *testing.T) {
	privKey, err := GenerateEphemeralKeyPair()
	if err != nil {
		t.Fatalf("GenerateEphemeralKeyPair failed: %v", err)
	}

	if privKey == nil {
		t.Fatal("Generated key is nil")
	}

	if privKey.Curve != elliptic.P256() {
		t.Errorf("Expected P256 curve, got %v", privKey.Curve.Params().Name)
	}

	// Key validity is ensured by ecdsa.GenerateKey
	// No need for explicit on-curve check (deprecated API)
}

func TestSerializeDeserializePublicKey(t *testing.T) {
	// Generate a key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Serialize public key
	serialized := SerializePublicKey(&privKey.PublicKey)
	if serialized == nil {
		t.Fatal("SerializePublicKey returned nil")
	}

	// Verify serialized format (should be 64 bytes: X + Y coordinates)
	if len(serialized) != 64 {
		t.Errorf("Expected 64-byte serialized key, got %d bytes", len(serialized))
	}

	// Deserialize
	pubKey, err := DeserializePublicKey(serialized)
	if err != nil {
		t.Fatalf("DeserializePublicKey failed: %v", err)
	}

	// Verify deserialized key matches original
	if pubKey.X.Cmp(privKey.PublicKey.X) != 0 {
		t.Error("Deserialized X coordinate does not match")
	}

	if pubKey.Y.Cmp(privKey.PublicKey.Y) != 0 {
		t.Error("Deserialized Y coordinate does not match")
	}
}

func TestFullECDHFlow(t *testing.T) {
	// Simulate agent and C2 key exchange
	agentPrivKey, err := GenerateEphemeralKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate agent key: %v", err)
	}

	c2PrivKey, err := GenerateEphemeralKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate C2 key: %v", err)
	}

	// Serialize public keys for transmission
	agentPubKeySerialized := SerializePublicKey(&agentPrivKey.PublicKey)
	if agentPubKeySerialized == nil {
		t.Fatal("Failed to serialize agent public key")
	}

	c2PubKeySerialized := SerializePublicKey(&c2PrivKey.PublicKey)
	if c2PubKeySerialized == nil {
		t.Fatal("Failed to serialize C2 public key")
	}

	// Deserialize on the other side
	agentPubKey, err := DeserializePublicKey(agentPubKeySerialized)
	if err != nil {
		t.Fatalf("Failed to deserialize agent public key: %v", err)
	}

	c2PubKey, err := DeserializePublicKey(c2PubKeySerialized)
	if err != nil {
		t.Fatalf("Failed to deserialize C2 public key: %v", err)
	}

	// Perform ECDH on both sides
	agentSharedSecret, err := PerformECDH(agentPrivKey, c2PubKey)
	if err != nil {
		t.Fatalf("Agent ECDH failed: %v", err)
	}

	c2SharedSecret, err := PerformECDH(c2PrivKey, agentPubKey)
	if err != nil {
		t.Fatalf("C2 ECDH failed: %v", err)
	}

	// Verify shared secrets match
	if len(agentSharedSecret) != len(c2SharedSecret) {
		t.Fatal("Shared secrets have different lengths")
	}

	for i := range agentSharedSecret {
		if agentSharedSecret[i] != c2SharedSecret[i] {
			t.Fatal("Shared secrets do not match")
		}
	}

	// Derive session keys
	agentSessionKey, err := DeriveSessionKey(agentSharedSecret, "test-agent-uuid")
	if err != nil {
		t.Fatalf("Agent session key derivation failed: %v", err)
	}

	c2SessionKey, err := DeriveSessionKey(c2SharedSecret, "test-agent-uuid")
	if err != nil {
		t.Fatalf("C2 session key derivation failed: %v", err)
	}

	// Verify session keys match
	for i := range agentSessionKey {
		if agentSessionKey[i] != c2SessionKey[i] {
			t.Fatal("Session keys do not match")
		}
	}

	t.Logf("Successfully completed full ECDH flow with matching session keys")
}
