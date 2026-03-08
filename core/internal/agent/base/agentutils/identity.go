package agentutils

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"os"
	"sync"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"golang.org/x/crypto/hkdf"
)

var (
	// AgentKey is the unique ephemeral key for this agent session
	AgentKey     *ecdsa.PrivateKey
	agentKeyOnce sync.Once
)

// GetAgentKey generates a random, ephemeral agent key.
// It uses sync.Once to ensure the key persists for the process lifetime
// (critical for stagers/shellcode stability) but is lost on restart.
func GetAgentKey() error {
	var err error
	agentKeyOnce.Do(func() {
		// If running under stager, try to derive key from injected seed (FD 3)
		if common.RuntimeConfig != nil && common.RuntimeConfig.IsRunByStager {
			// Standard "Seed" FD is 3
			seedFile := os.NewFile(uintptr(3), "stager_seed_fd")
			if seedFile != nil {
				seed := make([]byte, 32)
				n, readErr := io.ReadFull(seedFile, seed)
				seedFile.Close() // Close immediately

				if readErr == nil && n == 32 {
					// Use SHA256 of seed for logging to avoid leaking raw seed while allowing verification
					seedHash := sha256.Sum256(seed)
					logging.Infof("Deriving agent key from stager seed (FD 3, hash: %x)...", seedHash[:8])

					// Use HKDF to derive a stream of bytes for ECDSA key generation
					// We use SHA256 as hash, seed as secret, no salt, fixed info
					hkdfReader := hkdf.New(sha256.New, seed, nil, []byte("host identity verification"))
					derivedBytes := make([]byte, 32)
					_, err = io.ReadFull(hkdfReader, derivedBytes)
					if err != nil {
						logging.Warningf("Failed to read from HKDF: %v", err)
						return
					}

					// Use crypto/ecdh for standard-compliant P-256 private key derivation
					ecdhKey, ecdhErr := ecdh.P256().NewPrivateKey(derivedBytes)
					if ecdhErr != nil {
						logging.Warningf("Failed to derive ECDH key: %v, falling back to random", ecdhErr)
					} else {
						// Convert ECDH private key to ECDSA
						AgentKey = new(ecdsa.PrivateKey)
						AgentKey.Curve = elliptic.P256()
						AgentKey.D = new(big.Int).SetBytes(ecdhKey.Bytes())
						// Derive Public Key coordinates from ECDH seamlessly
						pubBytes := ecdhKey.PublicKey().Bytes()
						AgentKey.PublicKey.X = new(big.Int).SetBytes(pubBytes[1:33])
						AgentKey.PublicKey.Y = new(big.Int).SetBytes(pubBytes[33:])

						// Log public key thumbprint for verification
						pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&AgentKey.PublicKey)
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
		AgentKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	})

	if err != nil {
		return fmt.Errorf("failed to generate ephemeral key: %v", err)
	}
	return nil
}

// RenewAgentKey force-regenerates the ephemeral agent key.
// Primarily used for testing key rotation scenarios.
func RenewAgentKey() error {
	var err error
	logging.Infof("Renewing ephemeral agent key...")
	AgentKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to renew ephemeral key: %v", err)
	}
	return nil
}

// SignWithAgentKey signs data with the agent's unique key
func SignWithAgentKey(data []byte) ([]byte, error) {
	if AgentKey == nil {
		if err := GetAgentKey(); err != nil {
			return nil, fmt.Errorf("get key: %v", err)
		}
	}
	return transport.SignJSONWithKey(AgentKey, data)
}
