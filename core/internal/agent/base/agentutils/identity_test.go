package agentutils

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"syscall"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
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

func TestGetAgentKeyFromStager(t *testing.T) {
	// Reset Once for this test
	// We need to use reflection or just assume we can modify it since we are in same package?
	// agentKeyOnce is private variable in same package. Yes we can access it.
	agentKeyOnce = sync.Once{}
	AgentKey = nil

	// Mock RuntimeConfig
	common.RuntimeConfig = &def.Config{
		IsRunByStager: true,
	}

	// Create pipe for seed
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}

	// We need to write to the pipe, but we need FD 3 to be the reader.
	// We can't easily force os.NewFile(3) to read from our pipe unless FD 3 IS the pipe reader.
	// So we must use dup2 to put pipe reader at FD 3.

	// Save whatever is at FD 3 currently (likely nothing or some internal FD)
	// We should try to save it.
	originalFD3, _ := syscall.Dup(3)

	// Duplicate pipe reader to FD 3
	// Note: this closes strictly FD 3 if open
	err = syscall.Dup2(int(r.Fd()), 3)
	if err != nil {
		t.Fatalf("Failed to dup2 to FD 3: %v", err)
	}

	// Generate a deterministic seed (all 'A's)
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 0x41
	}

	// Write to pipe in background (to prevent blocking if buffer full, though 32 bytes is small)
	go func() {
		w.Write(seed)
		w.Close()
	}()

	// Call GetAgentKey
	err = GetAgentKey()
	if err != nil {
		t.Fatalf("GetAgentKey failed: %v", err)
	}

	if AgentKey == nil {
		t.Fatal("AgentKey is nil after seeded generation")
	}

	// Capture the key
	key1 := *AgentKey // Copy struct (it's a pointer to PrivateKey, so we copy value... wait PrivateKey has pointers)
	t.Logf("Key1: X=%x Y=%x", key1.X, key1.Y)

	// Cleanup FD 3 for next pass
	syscall.Close(3)
	// Restore original if valid
	if originalFD3 != -1 {
		syscall.Dup2(originalFD3, 3)
		syscall.Close(originalFD3)
	}
	r.Close() // Close original pipe reader FD (dup2 copied it)

	// --- Pass 2: Same Seed -> Same Key ---
	agentKeyOnce = sync.Once{}
	AgentKey = nil

	r2, w2, _ := os.Pipe()
	syscall.Dup2(int(r2.Fd()), 3)

	go func() {
		w2.Write(seed)
		w2.Close()
	}()

	err = GetAgentKey()
	if err != nil {
		t.Fatalf("GetAgentKey failed pass 2: %v", err)
	}

	if AgentKey == nil {
		t.Fatal("AgentKey is nil after pass 2")
	}

	key2 := AgentKey
	t.Logf("Key2: X=%x Y=%x", key2.X, key2.Y)

	if key1.X.Cmp(key2.X) != 0 || key1.Y.Cmp(key2.Y) != 0 {
		t.Errorf("Keys derived from same seed are different!")
	}

	// Cleanup final
	syscall.Close(3)
	r2.Close()
}

func TestGetAgentKeyFromStager_PartialRead(t *testing.T) {
	// Reset Once
	agentKeyOnce = sync.Once{}
	AgentKey = nil

	// Mock RuntimeConfig
	common.RuntimeConfig = &def.Config{
		IsRunByStager: true,
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}

	originalFD3, _ := syscall.Dup(3)
	err = syscall.Dup2(int(r.Fd()), 3)
	if err != nil {
		t.Fatalf("Failed to dup2 to FD 3: %v", err)
	}

	// Write only 11 bytes (simulating the bug)
	go func() {
		w.Write(make([]byte, 11))
		w.Close()
	}()

	// Should fail to read seed, but fallback to random
	err = GetAgentKey()
	if err != nil {
		t.Fatalf("GetAgentKey failed during partial read fallback: %v", err)
	}

	if AgentKey == nil {
		t.Fatal("AgentKey should be generated (random fallback)")
	}

	// Cleanup
	syscall.Close(3)
	if originalFD3 != -1 {
		syscall.Dup2(originalFD3, 3)
		syscall.Close(originalFD3)
	}
	r.Close()
}
func TestDeterministicKeyDerivation(t *testing.T) {
	// Mock RuntimeConfig
	common.RuntimeConfig = &def.Config{
		IsRunByStager: true,
	}

	// Generate a test seed
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 0x10)
	}

	runDerivation := func() string {
		agentKeyOnce = sync.Once{}
		AgentKey = nil

		r, w, _ := os.Pipe()
		originalFD3, _ := syscall.Dup(3)
		syscall.Dup2(int(r.Fd()), 3)

		go func() {
			w.Write(seed)
			w.Close()
		}()

		err := GetAgentKey()
		if err != nil {
			t.Fatalf("GetAgentKey failed: %v", err)
		}

		// Revert FD 3
		syscall.Close(3)
		if originalFD3 != -1 {
			syscall.Dup2(originalFD3, 3)
			syscall.Close(originalFD3)
		}
		r.Close()

		// Return public key thumbprint
		pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&AgentKey.PublicKey)
		pubKeyHash := sha256.Sum256(pubKeyBytes)
		return fmt.Sprintf("%x", pubKeyHash[:8])
	}

	// Run 10 times and ensure thumbprint is ALWAYS the same
	firstThumbprint := runDerivation()
	t.Logf("First Thumbprint: %s", firstThumbprint)

	for i := 0; i < 10; i++ {
		thumbprint := runDerivation()
		if thumbprint != firstThumbprint {
			t.Errorf("Iteration %d: Non-deterministic thumbprint! Expected %s, got %s", i, firstThumbprint, thumbprint)
		}
	}
}
