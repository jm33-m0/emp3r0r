package controllers

import (
	"os"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

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
	configPayload, agentUUID, err := EncryptAgentConfig()
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
	tests := []struct {
		name        string
		payloadType string
		arch        string
		wantStub    string
		wantOut     string
	}{
		{
			name:        "Linux executable",
			payloadType: "linux_executable",
			arch:        "amd64",
			wantStub:    "stub-amd64",
			wantOut:     "agent_linux_amd64_",
		},
		{
			name:        "Windows executable",
			payloadType: "windows_executable",
			arch:        "amd64",
			wantStub:    "stub-win-amd64",
			wantOut:     "agent_windows_amd64_",
		},
		{
			name:        "Windows DLL",
			payloadType: "windows_dll",
			arch:        "386",
			wantStub:    "stub-win-386.dll",
			wantOut:     "agent_windows_386_",
		},
		{
			name:        "Linux SO",
			payloadType: "linux_so",
			arch:        "arm64",
			wantStub:    "stub-arm64.so",
			wantOut:     "agent_linux_so_arm64_",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, _ := os.MkdirTemp("", "emp3r0r_path_test")
			defer os.RemoveAll(tmpDir)

			cfg := AgentBuildConfig{
				PayloadType: tt.payloadType,
				Arch:        tt.arch,
				WorkSpace:   tmpDir,
			}

			stubFile, outFile := GenerateFilePaths(cfg)

			// Check stub file contains expected pattern
			if !contains(stubFile, tt.wantStub) {
				t.Errorf("Stub file mismatch. Got %s, want to contain %s", stubFile, tt.wantStub)
			}

			// Check output file contains expected pattern
			if !contains(outFile, tt.wantOut) {
				t.Errorf("Output file mismatch. Got %s, want to contain %s", outFile, tt.wantOut)
			}
		})
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
	os.WriteFile(stubFile, stubContent, 0644)

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
