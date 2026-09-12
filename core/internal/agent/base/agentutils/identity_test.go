//go:build linux

package agentutils

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io"
	"os"
	"sync"
	"syscall"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// resetIdentityForTest clears the package-level identity state so each test
// derives a fresh key. Tests run sequentially in this package, so the direct
// assignments are safe.
func resetIdentityForTest() {
	agentKeyOnce = sync.Once{}
	AgentKey = nil
	supervised.Store(false)
}

// withStager configures the package as if a launcher started the agent.
func withStager(t *testing.T) {
	t.Helper()
	orig := common.RuntimeConfig
	common.RuntimeConfig = &def.Config{IsRunByStager: true}
	t.Cleanup(func() { common.RuntimeConfig = orig })
}

func restoreFD(t *testing.T, fd int, saved int) {
	t.Helper()
	if saved >= 0 {
		if err := syscall.Dup2(saved, fd); err != nil {
			t.Fatalf("Failed to restore FD %d: %v", fd, err)
		}
		_ = syscall.Close(saved)
		return
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("Failed to open %s: %v", os.DevNull, err)
	}
	defer devNull.Close()
	if err := syscall.Dup2(int(devNull.Fd()), fd); err != nil {
		t.Fatalf("Failed to bind %s to FD %d: %v", os.DevNull, fd, err)
	}
}

// withKeyFDs wires FD 3 (launcher -> agent) to `in` and returns a reader for
// what the agent writes to FD 4 (agent -> launcher).
func withKeyFDs(t *testing.T, in []byte) func() []byte {
	t.Helper()

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create key-in pipe: %v", err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create key-out pipe: %v", err)
	}

	saved3, _ := syscall.Dup(agentKeyInFD)
	saved4, _ := syscall.Dup(agentKeyOutFD)
	if err := syscall.Dup2(int(inR.Fd()), agentKeyInFD); err != nil {
		t.Fatalf("bind key-in pipe to FD %d: %v", agentKeyInFD, err)
	}
	if err := syscall.Dup2(int(outW.Fd()), agentKeyOutFD); err != nil {
		t.Fatalf("bind key-out pipe to FD %d: %v", agentKeyOutFD, err)
	}

	// Feed the (possibly empty) input synchronously, then close so the agent
	// observes EOF when there is no cached key.
	if len(in) > 0 {
		if _, err := inW.Write(in); err != nil {
			t.Fatalf("write key-in: %v", err)
		}
	}
	_ = inW.Close()

	t.Cleanup(func() {
		restoreFD(t, agentKeyInFD, saved3)
		restoreFD(t, agentKeyOutFD, saved4)
		_ = inR.Close()
		_ = outW.Close()
	})

	return func() []byte {
		buf := make([]byte, p256ScalarLen)
		if _, err := io.ReadFull(outR, buf); err != nil {
			t.Fatalf("read exported key: %v", err)
		}
		return buf
	}
}

func pubDER(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return der
}

func TestEncodeParseAgentKeyRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	encoded := encodeAgentKey(key)
	if len(encoded) != p256ScalarLen {
		t.Fatalf("encoded key length = %d, want %d", len(encoded), p256ScalarLen)
	}

	parsed, ok := parsePreservedAgentKey(bytes.NewReader(encoded))
	if !ok {
		t.Fatal("parsePreservedAgentKey rejected a valid key")
	}
	if !bytes.Equal(pubDER(t, key), pubDER(t, parsed)) {
		t.Fatal("round-tripped key pair differs from the original")
	}

	// Truncated input must be rejected, not silently accepted.
	if _, ok := parsePreservedAgentKey(bytes.NewReader(encoded[:p256ScalarLen-1])); ok {
		t.Fatal("parsePreservedAgentKey accepted a truncated key")
	}
}

// TestGetAgentKeyRestoresFromLauncher is the regression guard for recycled
// agent processes: the launcher's cached key pair must come back exactly.
func TestGetAgentKeyRestoresFromLauncher(t *testing.T) {
	resetIdentityForTest()
	withStager(t)

	original, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	readExported := withKeyFDs(t, encodeAgentKey(original))

	if err := GetAgentKey(); err != nil {
		t.Fatalf("GetAgentKey: %v", err)
	}
	if AgentKey == nil {
		t.Fatal("AgentKey is nil after restore")
	}
	if !bytes.Equal(pubDER(t, original), pubDER(t, AgentKey)) {
		t.Fatal("agent did not restore the launcher-provided key pair")
	}
	if got := readExported(); !bytes.Equal(got, encodeAgentKey(original)) {
		t.Fatal("agent did not hand the restored key back to the launcher")
	}
}

// TestGetAgentKeyGeneratesAndExports covers the first lifecycle: no cached key,
// so the agent must generate one and hand it to the launcher.
func TestGetAgentKeyGeneratesAndExports(t *testing.T) {
	resetIdentityForTest()
	withStager(t)

	readExported := withKeyFDs(t, nil)

	if err := GetAgentKey(); err != nil {
		t.Fatalf("GetAgentKey: %v", err)
	}
	if AgentKey == nil {
		t.Fatal("AgentKey is nil after generation")
	}
	if got := readExported(); !bytes.Equal(got, encodeAgentKey(AgentKey)) {
		t.Fatal("agent did not export its freshly generated key")
	}
}

func TestGetAgentKey(t *testing.T) {
	resetIdentityForTest()
	orig := common.RuntimeConfig
	common.RuntimeConfig = &def.Config{}
	t.Cleanup(func() { common.RuntimeConfig = orig })

	err := GetAgentKey()
	if err != nil {
		t.Fatalf("GetAgentKey failed: %v", err)
	}

	if AgentKey == nil {
		t.Fatal("AgentKey is nil after GetAgentKey")
	}
	if AgentKey.Curve != elliptic.P256() {
		t.Errorf("Expected P256 curve, got %v", AgentKey.Curve.Params().Name)
	}

	firstKey := AgentKey
	if err = GetAgentKey(); err != nil {
		t.Fatalf("Second GetAgentKey call failed: %v", err)
	}
	if AgentKey != firstKey {
		t.Error("GetAgentKey should return the same key on subsequent calls (sync.Once)")
	}
}

func TestSignWithAgentKey(t *testing.T) {
	resetIdentityForTest()
	orig := common.RuntimeConfig
	common.RuntimeConfig = &def.Config{}
	t.Cleanup(func() { common.RuntimeConfig = orig })

	if err := GetAgentKey(); err != nil {
		t.Fatalf("GetAgentKey failed: %v", err)
	}

	signature, err := SignWithAgentKey([]byte("test message"))
	if err != nil {
		t.Fatalf("SignWithAgentKey failed: %v", err)
	}
	if len(signature) == 0 {
		t.Error("Signature is empty")
	}
	if len(signature) < 60 || len(signature) > 72 {
		t.Errorf("Unexpected signature length: %d", len(signature))
	}
}

func TestEphemeralKeyUniqueness(t *testing.T) {
	resetIdentityForTest()
	orig := common.RuntimeConfig
	common.RuntimeConfig = &def.Config{}
	t.Cleanup(func() { common.RuntimeConfig = orig })

	if err := GetAgentKey(); err != nil {
		t.Fatalf("GetAgentKey failed: %v", err)
	}
	if AgentKey.D == nil || AgentKey.D.Sign() == 0 {
		t.Error("Private key D component is invalid")
	}
	if AgentKey.X == nil || AgentKey.Y == nil {
		t.Error("Public key components are invalid")
	}
}
