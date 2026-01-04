package common

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
)

func TestInitConfig(t *testing.T) {
	// 1. Prepare a config
	cfg := &def.Config{
		CCAddress:            "127.0.0.1",
		AgentSocksServerPort: "54321", // Use a high port to avoid conflict
		AgentRoot:            "agent_root_test",
		PIDFile:              "agent.pid",
		SocketName:           "agent.sock",
		UtilsPath:            "utils",
		Password:             "password",
	}

	// 2. Marshal to CBOR
	cborData, err := cbor.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// 3. Encrypt
	encryptedData, err := crypto.AES_GCM_Encrypt([]byte(def.MagicString), cborData)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// 4. Inject into def.AgentConfig
	def.AgentConfig = encryptedData

	// 5. Run InitConfig
	err = InitConfig()
	if err != nil {
		t.Fatalf("InitConfig failed: %v", err)
	}

	// 6. Verify RuntimeConfig
	if RuntimeConfig.CCAddress != "127.0.0.1" {
		t.Errorf("CCAddress mismatch: %s", RuntimeConfig.CCAddress)
	}

	t.Logf("AgentRoot: %s", RuntimeConfig.AgentRoot)
	t.Logf("PIDFile: %s", RuntimeConfig.PIDFile)

	// Verify PIDFile is constructed correctly
	// It should contain the AgentRoot and the PIDFile name
	// RuntimeConfig.PIDFile = fmt.Sprintf("%s/%s", RuntimeConfig.AgentRoot, RuntimeConfig.PIDFile)
	// So it should end with "agent.pid"
	expectedSuffix := "/agent.pid"
	if len(RuntimeConfig.PIDFile) < len(expectedSuffix) || RuntimeConfig.PIDFile[len(RuntimeConfig.PIDFile)-len(expectedSuffix):] != expectedSuffix {
		t.Errorf("PIDFile malformed: %s", RuntimeConfig.PIDFile)
	}
}
