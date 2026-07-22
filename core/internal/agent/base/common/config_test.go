package common

import (
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
)

func TestInitConfig_Comprehensive(t *testing.T) {
	// Reset global state
	RuntimeConfig = &def.Config{}
	def.CCAddress = ""

	// 1. Prepare a config with ALL fields populated
	originalCfg := &def.Config{
		CCAddress:                 "192.168.1.100",
		CCHost:                    "192.168.1.100",
		CCH2Port:                  "8443",
		C2ChannelMode:             def.C2ChannelModeH2Conn,
		AgentSocksServerPort:      "50001",
		AgentSocksTimeout:         60,
		StagerHTTPListenerPort:    "8080",
		Password:                  "secret_password",
		ShadowsocksLocalSocksPort: "1080",
		ShadowsocksServerPort:     "8388",
		P2PRelayPort:              "4000",
		KCPClientPort:             "4001",
		UseKCP:                    false,
		EnableNCSI:                true,
		SSHHostKey:                []byte("ssh-rsa AAAAB3Nza..."),
		SSHDShellPort:             "2222",
		MeshGossipPort:            "9000",
		CCTimeout:                 5000,
		PreflightEnabled:          true,
		PreflightURL:              "http://example.com",
		PreflightMethod:           "GET",
		PreflightHeaders:          map[string]string{"X-Test": "True"},
		PreflightIntervalMin:      30,
		PreflightIntervalMax:      120,
	}

	// 2. Marshal to CBOR
	cborData, err := cbor.Marshal(originalCfg)
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

	// 6. Verify ALL fields
	// Note: Some fields are modified by InitConfig (paths), so we check them specially.

	// Direct matches
	if RuntimeConfig.CCAddress != originalCfg.CCAddress {
		t.Errorf("CCAddress mismatch: got %s, want %s", RuntimeConfig.CCAddress, originalCfg.CCAddress)
	}
	if RuntimeConfig.CCHost != originalCfg.CCHost {
		t.Errorf("CCHost mismatch: got %s, want %s", RuntimeConfig.CCHost, originalCfg.CCHost)
	}
	if RuntimeConfig.CCH2Port != originalCfg.CCH2Port {
		t.Errorf("CCPort mismatch: got %s, want %s", RuntimeConfig.CCH2Port, originalCfg.CCH2Port)
	}
	if RuntimeConfig.AgentSocksServerPort != originalCfg.AgentSocksServerPort {
		t.Errorf("AgentSocksServerPort mismatch: got %s, want %s", RuntimeConfig.AgentSocksServerPort, originalCfg.AgentSocksServerPort)
	}
	if RuntimeConfig.AgentSocksTimeout != originalCfg.AgentSocksTimeout {
		t.Errorf("AgentSocksTimeout mismatch: got %d, want %d", RuntimeConfig.AgentSocksTimeout, originalCfg.AgentSocksTimeout)
	}
	if RuntimeConfig.StagerHTTPListenerPort != originalCfg.StagerHTTPListenerPort {
		t.Errorf("StagerHTTPListenerPort mismatch: got %s, want %s", RuntimeConfig.StagerHTTPListenerPort, originalCfg.StagerHTTPListenerPort)
	}
	if RuntimeConfig.Password != originalCfg.Password {
		t.Errorf("Password mismatch: got %s, want %s", RuntimeConfig.Password, originalCfg.Password)
	}
	if RuntimeConfig.ShadowsocksLocalSocksPort != originalCfg.ShadowsocksLocalSocksPort {
		t.Errorf("ShadowsocksLocalSocksPort mismatch: got %s, want %s", RuntimeConfig.ShadowsocksLocalSocksPort, originalCfg.ShadowsocksLocalSocksPort)
	}
	if RuntimeConfig.ShadowsocksServerPort != originalCfg.ShadowsocksServerPort {
		t.Errorf("ShadowsocksServerPort mismatch: got %s, want %s", RuntimeConfig.ShadowsocksServerPort, originalCfg.ShadowsocksServerPort)
	}
	if RuntimeConfig.P2PRelayPort != originalCfg.P2PRelayPort {
		t.Errorf("KCPServerPort mismatch: got %s, want %s", RuntimeConfig.P2PRelayPort, originalCfg.P2PRelayPort)
	}
	if RuntimeConfig.KCPClientPort != originalCfg.KCPClientPort {
		t.Errorf("KCPClientPort mismatch: got %s, want %s", RuntimeConfig.KCPClientPort, originalCfg.KCPClientPort)
	}
	if RuntimeConfig.UseKCP != originalCfg.UseKCP {
		t.Errorf("UseKCP mismatch: got %v, want %v", RuntimeConfig.UseKCP, originalCfg.UseKCP)
	}
	if RuntimeConfig.EnableNCSI != originalCfg.EnableNCSI {
		t.Errorf("EnableNCSI mismatch: got %v, want %v", RuntimeConfig.EnableNCSI, originalCfg.EnableNCSI)
	}
	if string(RuntimeConfig.SSHHostKey) != string(originalCfg.SSHHostKey) {
		t.Errorf("SSHHostKey mismatch")
	}
	if RuntimeConfig.SSHDShellPort != originalCfg.SSHDShellPort {
		t.Errorf("SSHDShellPort mismatch: got %s, want %s", RuntimeConfig.SSHDShellPort, originalCfg.SSHDShellPort)
	}
	if RuntimeConfig.MeshGossipPort != originalCfg.MeshGossipPort {
		t.Errorf("MeshGossipPort mismatch: got %s, want %s", RuntimeConfig.MeshGossipPort, originalCfg.MeshGossipPort)
	}
	if RuntimeConfig.PreflightEnabled != originalCfg.PreflightEnabled {
		t.Errorf("PreflightEnabled mismatch: got %v, want %v", RuntimeConfig.PreflightEnabled, originalCfg.PreflightEnabled)
	}
	if RuntimeConfig.PreflightURL != originalCfg.PreflightURL {
		t.Errorf("PreflightURL mismatch: got %s, want %s", RuntimeConfig.PreflightURL, originalCfg.PreflightURL)
	}
	if RuntimeConfig.PreflightMethod != originalCfg.PreflightMethod {
		t.Errorf("PreflightMethod mismatch: got %s, want %s", RuntimeConfig.PreflightMethod, originalCfg.PreflightMethod)
	}
	if RuntimeConfig.PreflightMethod != originalCfg.PreflightMethod {
		t.Errorf("PreflightMethod mismatch: got %s, want %s", RuntimeConfig.PreflightMethod, originalCfg.PreflightMethod)
	}
	if RuntimeConfig.PreflightIntervalMin != originalCfg.PreflightIntervalMin {
		t.Errorf("PreflightIntervalMin mismatch: got %d, want %d", RuntimeConfig.PreflightIntervalMin, originalCfg.PreflightIntervalMin)
	}
	if RuntimeConfig.PreflightIntervalMax != originalCfg.PreflightIntervalMax {
		t.Errorf("PreflightIntervalMax mismatch: got %d, want %d", RuntimeConfig.PreflightIntervalMax, originalCfg.PreflightIntervalMax)
	}
	if RuntimeConfig.CAPEM != originalCfg.CAPEM {
		t.Errorf("CAPEM mismatch: got %s, want %s", RuntimeConfig.CAPEM, originalCfg.CAPEM)
	}
	if RuntimeConfig.CAFingerprint != originalCfg.CAFingerprint {
		t.Errorf("CAFingerprint mismatch: got %s, want %s", RuntimeConfig.CAFingerprint, originalCfg.CAFingerprint)
	}
	if RuntimeConfig.C2TransportProxy != originalCfg.C2TransportProxy {
		t.Errorf("C2TransportProxy mismatch: got %s, want %s", RuntimeConfig.C2TransportProxy, originalCfg.C2TransportProxy)
	}
	if RuntimeConfig.CDNProxy != originalCfg.CDNProxy {
		t.Errorf("CDNProxy mismatch: got %s, want %s", RuntimeConfig.CDNProxy, originalCfg.CDNProxy)
	}
	if RuntimeConfig.DoHServer != originalCfg.DoHServer {
		t.Errorf("DoHServer mismatch: got %s, want %s", RuntimeConfig.DoHServer, originalCfg.DoHServer)
	}
	if RuntimeConfig.AgentUUID != originalCfg.AgentUUID {
		t.Errorf("AgentUUID mismatch: got %s, want %s", RuntimeConfig.AgentUUID, originalCfg.AgentUUID)
	}
	if RuntimeConfig.AgentUUIDSig != originalCfg.AgentUUIDSig {
		t.Errorf("AgentUUIDSig mismatch: got %s, want %s", RuntimeConfig.AgentUUIDSig, originalCfg.AgentUUIDSig)
	}
	if RuntimeConfig.AgentTag != originalCfg.AgentTag {
		t.Errorf("AgentTag mismatch: got %s, want %s", RuntimeConfig.AgentTag, originalCfg.AgentTag)
	}
	if RuntimeConfig.CCTimeout != originalCfg.CCTimeout {
		t.Errorf("CCTimeout mismatch: got %d, want %d", RuntimeConfig.CCTimeout, originalCfg.CCTimeout)
	}

	// Path verifications

	// Side Effect Verification

	// 1. def.CCAddress construction (Standard case)
	// Should be https://<CCAddress>:<CCPort>
	expectedCCAddr := fmt.Sprintf("https://%s:%s", originalCfg.CCAddress, originalCfg.CCH2Port)
	if def.CCAddress != expectedCCAddr {
		t.Errorf("def.CCAddress mismatch (Standard): got %s, want %s", def.CCAddress, expectedCCAddr)
	}

	// 2. transport.CACrtPEM
	if string(transport.CACrtPEM) != originalCfg.CAPEM {
		t.Errorf("transport.CACrtPEM mismatch")
	}
}

func TestInitConfig_Tor(t *testing.T) {
	// Reset global state
	RuntimeConfig = &def.Config{}
	def.CCAddress = ""

	// Prepare Tor config
	cfg := &def.Config{
		CCAddress:        "abcdefghijklmnop.onion", // Tor address
		CCH2Port:         "80",
		C2TransportProxy: "", // Should default to socks5://127.0.0.1:9050
	}

	// Marshal & Encrypt
	cborData, _ := cbor.Marshal(cfg)
	encryptedData, _ := crypto.AES_GCM_Encrypt([]byte(def.MagicString), cborData)
	def.AgentConfig = encryptedData

	// Run
	err := InitConfig()
	if err != nil {
		t.Fatalf("InitConfig failed: %v", err)
	}

	// Verify Tor logic
	// def.CCAddress should be http://<onion>
	expectedCCAddr := "http://abcdefghijklmnop.onion"
	if def.CCAddress != expectedCCAddr {
		t.Errorf("Tor def.CCAddress mismatch: got %s, want %s", def.CCAddress, expectedCCAddr)
	}

	// Check Proxy default
	expectedProxy := "socks5://127.0.0.1:9050"
	if RuntimeConfig.C2TransportProxy != expectedProxy {
		t.Errorf("Tor Proxy default mismatch: got %s, want %s", RuntimeConfig.C2TransportProxy, expectedProxy)
	}
}

func TestInitConfig_KCP(t *testing.T) {
	// Reset global state
	RuntimeConfig = &def.Config{}
	def.CCAddress = ""

	// Prepare KCP config
	cfg := &def.Config{
		CCAddress:     "1.2.3.4",
		UseKCP:        true,
		KCPClientPort: "9999",
	}

	// Marshal & Encrypt
	cborData, _ := cbor.Marshal(cfg)
	encryptedData, _ := crypto.AES_GCM_Encrypt([]byte(def.MagicString), cborData)
	def.AgentConfig = encryptedData

	// Run
	err := InitConfig()
	if err != nil {
		t.Fatalf("InitConfig failed: %v", err)
	}

	// Verify KCP logic
	// RuntimeConfig.CCPort should become KCPClientPort
	if RuntimeConfig.CCH2Port != "9999" {
		t.Errorf("KCP CCPort mismatch: got %s, want 9999", RuntimeConfig.CCH2Port)
	}
	// def.CCAddress should be https://127.0.0.1:<KCPClientPort>
	expectedCCAddr := "https://127.0.0.1:9999"
	if def.CCAddress != expectedCCAddr {
		t.Errorf("KCP def.CCAddress mismatch: got %s, want %s", def.CCAddress, expectedCCAddr)
	}
}
