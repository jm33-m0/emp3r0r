package agentutils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
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
		logging.Infof("Generating ephemeral agent key (PFS enabled)...")
		AgentKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	})

	if err != nil {
		return fmt.Errorf("failed to generate ephemeral key: %v", err)
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
