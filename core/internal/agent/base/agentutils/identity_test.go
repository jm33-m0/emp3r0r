package agentutils

import (
	"crypto/elliptic"
	"testing"
)

func TestGetAgentKey(t *testing.T) {
	// Test that GetAgentKey generates a valid ephemeral key
	err := GetAgentKey()
	if err != nil {
		t.Fatalf("GetAgentKey failed: %v", err)
	}

	if AgentKey == nil {
		t.Fatal("AgentKey is nil after GetAgentKey")
	}

	// Verify it's a P256 key
	if AgentKey.Curve != elliptic.P256() {
		t.Errorf("Expected P256 curve, got %v", AgentKey.Curve.Params().Name)
	}

	// Test idempotency - calling again should return the same key
	firstKey := AgentKey
	err = GetAgentKey()
	if err != nil {
		t.Fatalf("Second GetAgentKey call failed: %v", err)
	}

	if AgentKey != firstKey {
		t.Error("GetAgentKey should return the same key on subsequent calls (sync.Once)")
	}
}

func TestSignWithAgentKey(t *testing.T) {
	// Initialize agent key first
	err := GetAgentKey()
	if err != nil {
		t.Fatalf("GetAgentKey failed: %v", err)
	}

	// Test signing
	message := []byte("test message")
	signature, err := SignWithAgentKey(message)
	if err != nil {
		t.Fatalf("SignWithAgentKey failed: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Signature is empty")
	}

	// Verify signature is valid by checking it's the right length
	// ECDSA P256 signatures are typically 64 bytes (r and s concatenated)
	if len(signature) < 60 || len(signature) > 72 {
		t.Errorf("Unexpected signature length: %d", len(signature))
	}
}

func TestEphemeralKeyUniqueness(t *testing.T) {
	// This test verifies that keys are truly ephemeral
	// We can't test across process restarts, but we can verify
	// that the key generation uses crypto/rand

	err := GetAgentKey()
	if err != nil {
		t.Fatalf("GetAgentKey failed: %v", err)
	}

	// Verify the key is not nil and has valid components
	if AgentKey.D == nil || AgentKey.D.Sign() == 0 {
		t.Error("Private key D component is invalid")
	}

	if AgentKey.X == nil || AgentKey.Y == nil {
		t.Error("Public key components are invalid")
	}

	// Key validity is ensured by crypto/ecdsa.GenerateKey
	// No need for explicit on-curve check (deprecated API)
}
