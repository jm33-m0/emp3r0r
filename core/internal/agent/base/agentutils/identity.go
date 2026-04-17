package agentutils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

var (
	// AgentKey is the unique ephemeral key for this agent session
	AgentKey     *ecdsa.PrivateKey
	agentKeyMu   sync.RWMutex
	agentKeyOnce sync.Once
)

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

// GetAgentKey generates a random, ephemeral agent key.
// It uses sync.Once to ensure the key persists for the process lifetime
// (critical for stagers/shellcode stability) but is lost on restart.
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

		// If running under stager, try to derive key from injected seed (FD 3)
		if common.RuntimeConfig != nil && common.RuntimeConfig.IsRunByStager {
			// Standard "Seed" FD is 3
			seedFile := os.NewFile(uintptr(3), "loader_seed_fd")
			if seedFile != nil {
				seed := make([]byte, 32)
				n, readErr := io.ReadFull(seedFile, seed)
				seedFile.Close() // Close immediately

				if readErr == nil && n == 32 {
					// Use SHA256 of seed for logging to avoid leaking raw seed while allowing verification
					seedHash := sha256.Sum256(seed)
					logging.Infof("Deriving agent key from stager seed (FD 3, hash: %x)...", seedHash[:8])

					// Use HKDF-SHA256 to derive fixed key material from the seed.
					derivedBytes, err := hkdf.Key(sha256.New, seed, nil, "host identity verification", 32)
					if err != nil {
						logging.Warningf("Failed to derive key material with HKDF: %v", err)
						return
					}

					// Parse via ecdsa API to avoid touching deprecated raw key fields.
					parsedKey, parseErr := ecdsa.ParseRawPrivateKey(elliptic.P256(), derivedBytes)
					if parseErr != nil {
						logging.Warningf("Failed to derive ECDSA key from seed: %v, falling back to random", parseErr)
					} else {
						setAgentKey(parsedKey)

						// Log public key thumbprint for verification
						pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&parsedKey.PublicKey)
						pubKeyHash := sha256.Sum256(pubKeyBytes)
						logging.Infof("Agent key derived from seed successfully. Public key thumbprint: %x", pubKeyHash[:8])
						return // Success
					}
				} else {
					logging.Warningf("Failed to read seed from FD 3 (n=%d, err=%v), falling back to random", n, readErr)
				}
			} else {
				logging.Warningf("FD 3 not available, falling back to random")
			}

			// If we are here, we failed to get key from seed or not running by stager logic didn't work as expected
			// If IsRunByStager is true, we should probably have failed hard if stealth is critical?
			// But for reliability, fallback is safer.
			// Ideally stager ALWAYS provides FD 3.
		}

		logging.Infof("Generating ephemeral agent key (PFS enabled)...")
		generatedKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		err = keyErr
		if keyErr == nil {
			setAgentKey(generatedKey)
		}
	})

	if err != nil {
		return fmt.Errorf("failed to generate ephemeral key: %v", err)
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
