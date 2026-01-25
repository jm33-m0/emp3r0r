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
		CCAddress:                      "192.168.1.100",
		CCHost:                         "192.168.1.100",
		CCPort:                         "8443",
		AgentSocksServerPort:           "50001",
		AgentSocksTimeout:              60,
		StagerHTTPListenerPort:         "8080",
		Password:                       "secret_password",
		ShadowsocksLocalSocksPort:      "1080",
		ShadowsocksServerPort:          "8388",
		KCPServerPort:                  "4000",
		KCPClientPort:                  "4001",
		UseKCP:                         false,
		EnableNCSI:                     true,
		SSHHostKey:                     []byte("ssh-rsa AAAAB3Nza..."),
		Bring2CCReverseProxyPort:       "6000",
		SSHDShellPort:                  "2222",
		ProxyChainBroadcastPort:        "9000",
		ProxyChainBroadcastIntervalMin: 30,
		ProxyChainBroadcastIntervalMax: 60,
		CCTimeout:                      5000,
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
	if RuntimeConfig.CCPort != originalCfg.CCPort {
		t.Errorf("CCPort mismatch: got %s, want %s", RuntimeConfig.CCPort, originalCfg.CCPort)
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
	if RuntimeConfig.KCPServerPort != originalCfg.KCPServerPort {
		t.Errorf("KCPServerPort mismatch: got %s, want %s", RuntimeConfig.KCPServerPort, originalCfg.KCPServerPort)
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
	if RuntimeConfig.Bring2CCReverseProxyPort != originalCfg.Bring2CCReverseProxyPort {
		t.Errorf("Bring2CCReverseProxyPort mismatch: got %s, want %s", RuntimeConfig.Bring2CCReverseProxyPort, originalCfg.Bring2CCReverseProxyPort)
	}
	if RuntimeConfig.SSHDShellPort != originalCfg.SSHDShellPort {
		t.Errorf("SSHDShellPort mismatch: got %s, want %s", RuntimeConfig.SSHDShellPort, originalCfg.SSHDShellPort)
	}
	if RuntimeConfig.ProxyChainBroadcastPort != originalCfg.ProxyChainBroadcastPort {
		t.Errorf("ProxyChainBroadcastPort mismatch: got %s, want %s", RuntimeConfig.ProxyChainBroadcastPort, originalCfg.ProxyChainBroadcastPort)
	}
	if RuntimeConfig.ProxyChainBroadcastIntervalMin != originalCfg.ProxyChainBroadcastIntervalMin {
		t.Errorf("ProxyChainBroadcastIntervalMin mismatch: got %d, want %d", RuntimeConfig.ProxyChainBroadcastIntervalMin, originalCfg.ProxyChainBroadcastIntervalMin)
	}
	if RuntimeConfig.ProxyChainBroadcastIntervalMax != originalCfg.ProxyChainBroadcastIntervalMax {
		t.Errorf("ProxyChainBroadcastIntervalMax mismatch: got %d, want %d", RuntimeConfig.ProxyChainBroadcastIntervalMax, originalCfg.ProxyChainBroadcastIntervalMax)
	}
	if RuntimeConfig.CCIndicatorURL != originalCfg.CCIndicatorURL {
		t.Errorf("CCIndicatorURL mismatch: got %s, want %s", RuntimeConfig.CCIndicatorURL, originalCfg.CCIndicatorURL)
	}
	if RuntimeConfig.CCIndicatorWaitMin != originalCfg.CCIndicatorWaitMin {
		t.Errorf("CCIndicatorWaitMin mismatch: got %d, want %d", RuntimeConfig.CCIndicatorWaitMin, originalCfg.CCIndicatorWaitMin)
	}
	if RuntimeConfig.CCIndicatorWaitMax != originalCfg.CCIndicatorWaitMax {
		t.Errorf("CCIndicatorWaitMax mismatch: got %d, want %d", RuntimeConfig.CCIndicatorWaitMax, originalCfg.CCIndicatorWaitMax)
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
	expectedCCAddr := fmt.Sprintf("https://%s:%s", originalCfg.CCAddress, originalCfg.CCPort)
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
		CCPort:           "80",
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
	if RuntimeConfig.CCPort != "9999" {
		t.Errorf("KCP CCPort mismatch: got %s, want 9999", RuntimeConfig.CCPort)
	}
	// def.CCAddress should be https://127.0.0.1:<KCPClientPort>
	expectedCCAddr := "https://127.0.0.1:9999"
	if def.CCAddress != expectedCCAddr {
		t.Errorf("KCP def.CCAddress mismatch: got %s, want %s", def.CCAddress, expectedCCAddr)
	}
}
