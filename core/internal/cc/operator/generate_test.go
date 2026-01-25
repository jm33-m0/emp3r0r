package operator

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/config"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func TestAgentConfigFlow(t *testing.T) {
	// 1. Setup temp config file (CC side)
	tmpFile, err := os.CreateTemp("", "emp3r0r.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	live.EmpConfigFile = tmpFile.Name()

	// Write partial config (CC side)
	// Missing: pid_file, socket_name, agent_uuid
	partialConfig := map[string]interface{}{
		"cc_address":              "127.0.0.1",
		"agent_socks_server_port": "1080",
	}
	data, _ := json.Marshal(partialConfig)
	os.WriteFile(live.EmpConfigFile, data, 0600)

	// 2. Parse JSON and fill defaults (CC side)
	var ccConfig def.Config
	err = config.ReadJSONConfig(data, &ccConfig)
	if err != nil {
		t.Fatalf("ReadJSONConfig failed: %v", err)
	}

	// 3. Marshal to CBOR (CC side)
	cborData, err := cbor.Marshal(ccConfig)
	if err != nil {
		t.Fatalf("CBOR Marshal failed: %v", err)
	}

	// 4. Encrypt (CC side)
	// Note: MagicString is used as key in actual code
	encryptedData, err := crypto.AES_GCM_Encrypt([]byte(def.MagicString), cborData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// --- Agent Side Simulation ---

	// 5. Decrypt (Agent side) using REAL agent code
	decryptedData, err := util.VerifyConfigData(encryptedData)
	if err != nil {
		t.Fatalf("util.VerifyConfigData failed: %v", err)
	}

	// 6. Parse CBOR (Agent side)
	var agentConfig def.Config
	err = def.ReadCBORConfig(decryptedData, &agentConfig)
	if err != nil {
		t.Fatalf("ReadCBORConfig failed: %v", err)
	}

	// 7. Verify Agent Config
	if agentConfig.CCAddress != "127.0.0.1" {
		t.Errorf("Agent CCAddress mismatch. Got %s, expected 127.0.0.1", agentConfig.CCAddress)
	}
	if agentConfig.AgentSocksServerPort != "1080" {
		t.Errorf("Agent AgentSocksServerPort mismatch. Got %s, expected 1080", agentConfig.AgentSocksServerPort)
	}
	if agentConfig.AgentSocksServerPort != "1080" {
		t.Errorf("Agent AgentSocksServerPort mismatch. Got %s, expected 1080", agentConfig.AgentSocksServerPort)
	}
}
