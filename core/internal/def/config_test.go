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
	if newConfig.C2ChannelMode != C2ChannelModeDefault {
		t.Errorf("Expected default C2ChannelMode %s, got %s", C2ChannelModeDefault, newConfig.C2ChannelMode)
	}
}

func TestReadCBORConfigFull(t *testing.T) {
	cfg := &Config{
		CCAddress:                 "127.0.0.1",
		CCHost:                    "localhost",
		CCH2Port:                  "8080",
		AgentSocksServerPort:      "1080",
		AgentSocksTimeout:         60,
		StagerHTTPListenerPort:    "80",
		Password:                  "password",
		ShadowsocksLocalSocksPort: "1081",
		ShadowsocksServerPort:     "8388",
		P2PRelayPort:              "4000",
		KCPClientPort:             "4001",
		UseKCP:                    true,
		EnableNCSI:                false,
		SSHHostKey:                []byte("dummy_key"),
		SSHDShellPort:             "2222",
		MeshGossipPort:            "9000",
		AgentUUID:                 "uuid",
		AgentUUIDSig:              "sig",
		AgentTag:                  "tag",
		CCTimeout:                 5000,
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

func TestReadCBORConfigKeepsExplicitC2ChannelMode(t *testing.T) {
	originalConfig := &Config{
		CCAddress:     "127.0.0.1:1337",
		C2ChannelMode: C2ChannelModeH2Conn,
	}
	cborData, err := cbor.Marshal(originalConfig)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	newConfig := &Config{}
	if err = ReadCBORConfig(cborData, newConfig); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}
	if newConfig.C2ChannelMode != C2ChannelModeH2Conn {
		t.Errorf("Expected C2ChannelMode %s, got %s", C2ChannelModeH2Conn, newConfig.C2ChannelMode)
	}
}

func TestReadCBORConfigSetsDefaultC2RoutesWhenMissing(t *testing.T) {
	originalConfig := &Config{
		CCAddress: "127.0.0.1:1337",
	}
	cborData, err := cbor.Marshal(originalConfig)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	newConfig := &Config{}
	if err = ReadCBORConfig(cborData, newConfig); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	if newConfig.C2Routes.Checkin != DefaultC2RouteCheckin {
		t.Errorf("Expected default checkin route %s, got %s", DefaultC2RouteCheckin, newConfig.C2Routes.Checkin)
	}
	if newConfig.C2Routes.Msg != DefaultC2RouteMsg {
		t.Errorf("Expected default msg route %s, got %s", DefaultC2RouteMsg, newConfig.C2Routes.Msg)
	}
	if newConfig.C2Routes.FTP != DefaultC2RouteFTP {
		t.Errorf("Expected default ftp route %s, got %s", DefaultC2RouteFTP, newConfig.C2Routes.FTP)
	}
	if newConfig.C2Routes.WWW != DefaultC2RouteWWW {
		t.Errorf("Expected default www route %s, got %s", DefaultC2RouteWWW, newConfig.C2Routes.WWW)
	}
	if newConfig.C2Routes.Proxy != DefaultC2RouteProxy {
		t.Errorf("Expected default proxy route %s, got %s", DefaultC2RouteProxy, newConfig.C2Routes.Proxy)
	}
}

func TestAgentConfigLength(t *testing.T) {
	if len(AgentConfig) != 4096 {
		t.Errorf("AgentConfig length is %d, expected 4096", len(AgentConfig))
	}
}
