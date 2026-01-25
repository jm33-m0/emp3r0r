package def

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestReadCBORConfig(t *testing.T) {
	// Create a sample config
	originalConfig := &Config{
		CCAddress: "127.0.0.1:1337",
		CCTimeout: 1000,
	}

	// Marshal to CBOR
	cborData, err := cbor.Marshal(originalConfig)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	// Unmarshal back
	newConfig := &Config{}
	err = ReadCBORConfig(cborData, newConfig)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Compare
	if newConfig.CCAddress != originalConfig.CCAddress {
		t.Errorf("Expected CCAddress %s, got %s", originalConfig.CCAddress, newConfig.CCAddress)
	}
	if newConfig.CCTimeout != originalConfig.CCTimeout {
		t.Errorf("Expected CCTimeout %d, got %d", originalConfig.CCTimeout, newConfig.CCTimeout)
	}
}

func TestReadCBORConfigFull(t *testing.T) {
	cfg := &Config{
		CCAddress:                      "127.0.0.1",
		CCHost:                         "localhost",
		CCPort:                         "8080",
		AgentSocksServerPort:           "1080",
		AgentSocksTimeout:              60,
		StagerHTTPListenerPort:         "80",
		Password:                       "password",
		ShadowsocksLocalSocksPort:      "1081",
		ShadowsocksServerPort:          "8388",
		KCPServerPort:                  "4000",
		KCPClientPort:                  "4001",
		UseKCP:                         true,
		EnableNCSI:                     false,
		SSHHostKey:                     []byte("key"),
		Bring2CCReverseProxyPort:       "6000",
		SSHDShellPort:                  "2222",
		ProxyChainBroadcastPort:        "9000",
		ProxyChainBroadcastIntervalMin: 10,
		ProxyChainBroadcastIntervalMax: 20,
		AgentUUID:                      "uuid",
		AgentUUIDSig:                   "sig",
		AgentTag:                       "tag",
		CCTimeout:                      5000,
	}

	data, err := cbor.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	newCfg := &Config{}
	err = ReadCBORConfig(data, newCfg)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Check a few fields
	if newCfg.CCAddress != cfg.CCAddress {
		t.Errorf("Mismatch CCAddress")
	}
}

func TestAgentConfigLength(t *testing.T) {
	if len(AgentConfig) != 4096 {
		t.Errorf("AgentConfig length is %d, expected 4096", len(AgentConfig))
	}
}
