package builder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func TestPayloadGOOS(t *testing.T) {
	cases := map[string]string{
		PayloadTypeLinuxExecutable:   "linux",
		PayloadTypeLinuxSO:           "linux",
		PayloadTypeWindowsExecutable: "windows",
		PayloadTypeWindowsDLL:        "windows",
	}
	for payloadType, want := range cases {
		if got := PayloadGOOS(payloadType); got != want {
			t.Errorf("PayloadGOOS(%q) = %q, want %q", payloadType, got, want)
		}
	}
}

func TestTransportSupportedOn(t *testing.T) {
	// SMB is Windows-only; kcp/mtls run everywhere. KCP is optional, so its
	// cases are asserted only when the build compiled it in.
	cases := []struct {
		transport string
		goos      string
		want      bool
	}{
		{"smb", "windows", true},
		{"smb", "linux", false},
		{"mtls", "windows", true},
		{"mtls", "linux", true},
		{"unknown-transport", "linux", false},
	}
	for _, tc := range cases {
		if got := transport.TransportSupportedOn(tc.transport, tc.goos); got != tc.want {
			t.Errorf("TransportSupportedOn(%q, %q) = %v, want %v", tc.transport, tc.goos, got, tc.want)
		}
	}
	if _, err := transport.GetTransportImplementationStrict("kcp"); err == nil {
		for _, goos := range []string{"windows", "linux"} {
			if !transport.TransportSupportedOn("kcp", goos) {
				t.Errorf("TransportSupportedOn(\"kcp\", %q) = false, want true", goos)
			}
		}
	}
}

func TestEncryptAgentConfig(t *testing.T) {
	// Setup temp config file
	tmpFile, err := os.CreateTemp("", "emp3r0r_test.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	live.EmpConfigFile = tmpFile.Name()

	// Setup minimal runtime config
	live.RuntimeConfig = &def.Config{
		CCAddress:            "127.0.0.1",
		AgentSocksServerPort: "1080",
	}

	// Test encryption
	cfg := AgentBuildConfig{
		AgentUUID:    "test-uuid",
		AgentUUIDSig: "test-sig",
	}
	configPayload, agentUUID, err := EncryptAgentConfig(cfg)
	if err != nil {
		// If CA not available, skip this test
		t.Skipf("Skipping test - CA cert not available: %v", err)
	}

	// Verify UUID was generated
	if agentUUID == "" {
		t.Error("Agent UUID should not be empty")
	}

	// Verify payload is not empty
	if len(configPayload) == 0 {
		t.Error("Config payload should not be empty")
	}

	// Verify we can decrypt it
	decryptedData, err := crypto.AES_GCM_Decrypt([]byte(def.MagicString), configPayload)
	if err != nil {
		t.Fatalf("Failed to decrypt config: %v", err)
	}

	// Verify we can unmarshal CBOR
	var config def.Config
	err = cbor.Unmarshal(decryptedData, &config)
	if err != nil {
		t.Fatalf("Failed to unmarshal CBOR: %v", err)
	}

	// Verify config values
	if config.CCAddress != "127.0.0.1" {
		t.Errorf("CCAddress mismatch. Got %s, expected 127.0.0.1", config.CCAddress)
	}
	if config.AgentSocksServerPort != "1080" {
		t.Errorf("AgentSocksServerPort mismatch. Got %s, expected 1080", config.AgentSocksServerPort)
	}
	if config.AgentUUID != agentUUID {
		t.Errorf("AgentUUID mismatch. Got %s, expected %s", config.AgentUUID, agentUUID)
	}
}

func TestAgentConfigFlow(t *testing.T) {
	// This is the full flow test from operator/generate_test.go
	// Testing: JSON → CBOR → Encrypt → Decrypt → CBOR → Verify

	// Setup temp config file
	tmpFile, err := os.CreateTemp("", "emp3r0r_flow.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	live.EmpConfigFile = tmpFile.Name()

	// Setup runtime config (CC side)
	live.RuntimeConfig = &def.Config{
		CCAddress:            "127.0.0.1",
		AgentSocksServerPort: "1080",
	}

	// Marshal to CBOR (CC side)
	cborData, err := cbor.Marshal(live.RuntimeConfig)
	if err != nil {
		t.Fatalf("CBOR Marshal failed: %v", err)
	}

	// Encrypt (CC side)
	encryptedData, err := crypto.AES_GCM_Encrypt([]byte(def.MagicString), cborData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// --- Agent Side Simulation ---

	// Decrypt (Agent side) using REAL agent code
	decryptedData, err := util.VerifyConfigData(encryptedData)
	if err != nil {
		t.Fatalf("util.VerifyConfigData failed: %v", err)
	}

	// Parse CBOR (Agent side)
	var agentConfig def.Config
	err = def.ReadCBORConfig(decryptedData, &agentConfig)
	if err != nil {
		t.Fatalf("ReadCBORConfig failed: %v", err)
	}

	// Verify Agent Config
	if agentConfig.CCAddress != "127.0.0.1" {
		t.Errorf("Agent CCAddress mismatch. Got %s, expected 127.0.0.1", agentConfig.CCAddress)
	}
	if agentConfig.AgentSocksServerPort != "1080" {
		t.Errorf("Agent AgentSocksServerPort mismatch. Got %s, expected 1080", agentConfig.AgentSocksServerPort)
	}
}

func TestGenerateFilePaths(t *testing.T) {
	agentUUID := "11111111-2222-4333-8444-555555555555"
	runtimeConfig := &def.Config{
		CCAddress:     "c2.example.com",
		C2ChannelMode: def.C2ChannelModePlainHTTP,
		CCHTTPPort:    "8080",
		PollInterval:  60,
		Jitter:        20,
	}
	tests := []struct {
		name        string
		payloadType string
		arch        string
		wantStub    string
		wantOut     string
	}{
		{
			name:        "Linux executable",
			payloadType: PayloadTypeLinuxExecutable,
			arch:        "amd64",
			wantStub:    "stub-amd64",
			wantOut:     "agent_linux_amd64_exe_http-poll_standalone_poll-60_jitter-20_c2.example.com_8080",
		},
		{
			name:        "Windows executable",
			payloadType: PayloadTypeWindowsExecutable,
			arch:        "amd64",
			wantStub:    "stub-win-amd64",
			wantOut:     "agent_windows_amd64_exe_http-poll_standalone_poll-60_jitter-20_c2.example.com_8080.exe",
		},
		{
			name:        "Windows DLL",
			payloadType: PayloadTypeWindowsDLL,
			arch:        "386",
			wantStub:    "stub-win-386.dll",
			wantOut:     "agent_windows_386_dll_http-poll_standalone_poll-60_jitter-20_c2.example.com_8080.dll",
		},
		{
			name:        "Linux SO",
			payloadType: PayloadTypeLinuxSO,
			arch:        "arm64",
			wantStub:    "stub-arm64.so",
			wantOut:     "agent_linux_arm64_so_http-poll_standalone_poll-60_jitter-20_c2.example.com_8080.so",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := AgentBuildConfig{
				PayloadType: tt.payloadType,
				Arch:        tt.arch,
				WorkSpace:   t.TempDir(),
				AgentUUID:   agentUUID,
			}

			stubFile, outFile := GenerateFilePaths(cfg, runtimeConfig)

			if got := filepath.Base(stubFile); got != tt.wantStub {
				t.Errorf("stub file = %q, want %q", got, tt.wantStub)
			}
			ext := payloadExtension(tt.payloadType)
			wantOut := strings.TrimSuffix(tt.wantOut, ext) + "_11111111" + ext
			if got := filepath.Base(outFile); got != wantOut {
				t.Errorf("output file = %q, want %q", got, wantOut)
			}
		})
	}
}

func TestGenerateFilePathsFeatureRich(t *testing.T) {
	agentUUID := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	runtimeConfig := &def.Config{
		CCAddress:         "https://c2.example.com:8443",
		C2ChannelMode:     def.C2ChannelModeH2Conn,
		CCH2Port:          "8443",
		IsP2PEnabled:      true,
		IsDirectC2Enabled: true,
		P2PTransport:      "mtls",
		P2PRelayPort:      "50000",
		MeshGossipPort:    "50001",
		InitialPeers:      []string{"1.2.3.4:7946"},
		UseKCP:            true,
		EnableNCSI:        true,
		IsRunByStager:     true,
		PersistentRouter:  true,
		DoHServer:         "https://1.1.1.1/dns-query",
		ECHServerName:     "c2.example.com",
		CDNProxy:          "wss://cdn.example.com/ws",
		C2TransportProxy:  "socks5://127.0.0.1:9050",
	}
	cfg := AgentBuildConfig{
		PayloadType: PayloadTypeWindowsDLL,
		Arch:        "amd64",
		WorkSpace:   t.TempDir(),
		AgentUUID:   agentUUID,
	}
	want := "agent_windows_amd64_dll_h2conn_gateway-mtls_kcp_ncsi_stager_persistent-router_" +
		"doh-1.1.1.1_ech-c2.example.com_cdn-cdn.example.com_proxy-socks5_" +
		"relay-50000_gossip-50001_peers-1_c2.example.com-8443_aaaaaaaa.dll"
	_, outFile := GenerateFilePaths(cfg, runtimeConfig)
	if got := filepath.Base(outFile); got != want {
		t.Fatalf("output file = %q, want %q", got, want)
	}

	quicCfg := AgentBuildConfig{
		PayloadType: PayloadTypeLinuxExecutable,
		Arch:        "amd64",
		WorkSpace:   t.TempDir(),
		AgentUUID:   agentUUID,
	}
	quicRuntime := &def.Config{
		CCAddress:     "c2.example.com",
		C2ChannelMode: def.C2ChannelModeQUIC,
		CCH2Port:      "443",
	}
	_, quicOut := GenerateFilePaths(quicCfg, quicRuntime)
	wantQuicSuffix := "_c2.example.com_443_aaaaaaaa"
	if got := filepath.Base(quicOut); !strings.HasSuffix(got, wantQuicSuffix) {
		t.Fatalf("QUIC output file = %q, want suffix %q", got, wantQuicSuffix)
	}
}

func TestPatchAgentBinary(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "emp3r0r_patch_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create stub file with placeholder
	stubFile := tmpDir + "/stub"
	stubContent := make([]byte, 8192)
	// Fill with 0xff placeholder at offset 1024
	for i := 1024; i < 1024+4096; i++ {
		stubContent[i] = 0xff
	}
	os.WriteFile(stubFile, stubContent, 0o644)

	// Create config payload
	configPayload := []byte("test config data")

	// Patch
	outFile := tmpDir + "/agent"
	err = PatchAgentBinary(stubFile, outFile, configPayload)
	if err != nil {
		t.Fatalf("PatchAgentBinary failed: %v", err)
	}

	// Verify output file exists
	if !util.IsExist(outFile) {
		t.Error("Output file was not created")
	}

	// Read and verify
	patchedContent, _ := os.ReadFile(outFile)

	// Verify config was patched in (first 16 bytes should match)
	found := false
	for i := 0; i < len(patchedContent)-len(configPayload); i++ {
		if string(patchedContent[i:i+len(configPayload)]) == string(configPayload) {
			found = true
			break
		}
	}
	if !found {
		t.Error("Config payload not found in patched binary")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		len(s) > len(substr) && s[len(s)-len(substr):] == substr ||
		len(s) > len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
