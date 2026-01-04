package config

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

func TestInitConfigFile(t *testing.T) {
	// Initialize RuntimeConfig if it's nil
	if live.RuntimeConfig == nil {
		live.RuntimeConfig = &def.Config{}
	}

	// Setup temp file for config
	tmpConfigFile, err := os.CreateTemp("", "emp3r0r.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpConfigFile.Name())
	tmpConfigFile.Close()

	// Save original EmpConfigFile and restore it after test
	originalEmpConfigFile := live.EmpConfigFile
	defer func() { live.EmpConfigFile = originalEmpConfigFile }()
	live.EmpConfigFile = tmpConfigFile.Name()

	// Setup temp file for CA Key
	tmpKeyFile, err := os.CreateTemp("", "ca-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	tmpKeyFile.Close()
	defer os.Remove(tmpKeyFile.Name())

	// Create temp file for CA cert
	tmpCrtFile, err := os.CreateTemp("", "emp3r0r-ca-crt-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	tmpCrtFile.Close()
	defer os.Remove(tmpCrtFile.Name())

	// Generate CA cert and key using transport.GenCerts
	_, err = transport.GenCerts(nil, tmpCrtFile.Name(), tmpKeyFile.Name(), "", "", true)
	if err != nil {
		t.Fatalf("GenCerts failed: %v", err)
	}

	// Save original CaKeyFile and restore it after test
	originalCaKeyFile := transport.CaKeyFile
	defer func() { transport.CaKeyFile = originalCaKeyFile }()
	transport.CaKeyFile = tmpKeyFile.Name()

	// Save original CaCrtFile and restore it after test
	originalCaCrtFile := transport.CaCrtFile
	defer func() { transport.CaCrtFile = originalCaCrtFile }()
	transport.CaCrtFile = tmpCrtFile.Name()

	ccHost := "127.0.0.1"
	err = InitConfigFile(ccHost)
	if err != nil {
		t.Fatalf("InitConfigFile failed: %v", err)
	}

	// Verify fields
	if live.RuntimeConfig.CCAddress != ccHost {
		t.Errorf("Expected CCAddress %s, got %s", ccHost, live.RuntimeConfig.CCAddress)
	}

	// Check if ports are valid integers
	checkPort := func(name, portStr string) {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			t.Errorf("%s is not a valid integer: %s", name, portStr)
			return
		}
		if port < 1025 || port > 65534 {
			t.Errorf("%s is out of range (1025-65534): %d", name, port)
		}
	}

	checkPort("CCPort", live.RuntimeConfig.CCPort)
	checkPort("AgentSocksServerPort", live.RuntimeConfig.AgentSocksServerPort)
	checkPort("SSHDShellPort", live.RuntimeConfig.SSHDShellPort)

	// Check if UUID is set
	if live.RuntimeConfig.AgentUUID == "" {
		t.Error("AgentUUID is empty")
	}

	// Check if SSHHostKey is generated
	if len(live.RuntimeConfig.SSHHostKey) == 0 {
		t.Error("SSHHostKey is empty")
	}

	// Check if AgentUUIDSig is set
	if live.RuntimeConfig.AgentUUIDSig == "" {
		t.Error("AgentUUIDSig is empty")
	}
}

func TestSaveConfigJSON(t *testing.T) {
	// Setup temp file for config
	tmpFile, err := os.CreateTemp("", "emp3r0r.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Save original EmpConfigFile and restore it after test
	originalEmpConfigFile := live.EmpConfigFile
	defer func() { live.EmpConfigFile = originalEmpConfigFile }()

	live.EmpConfigFile = tmpFile.Name()

	// Setup a dummy RuntimeConfig
	live.RuntimeConfig = &def.Config{
		CCAddress:            "test.example.com",
		CCPort:               "9999",
		AgentSocksServerPort: "1080",
	}

	// Test SaveConfigJSON
	err = SaveConfigJSON()
	if err != nil {
		t.Fatalf("SaveConfigJSON failed: %v", err)
	}

	// Read back the file
	data, err := os.ReadFile(live.EmpConfigFile)
	if err != nil {
		t.Fatalf("Failed to read saved config file: %v", err)
	}

	var loadedConfig def.Config
	err = readJSONConfig(data, &loadedConfig)
	if err != nil {
		t.Fatalf("Failed to read saved config: %v", err)
	}

	if loadedConfig.CCAddress != "test.example.com" {
		t.Errorf("Loaded config mismatch. Expected CCAddress 'test.example.com', got '%s'", loadedConfig.CCAddress)
	}
	if loadedConfig.CCPort != "9999" {
		t.Errorf("Loaded config mismatch. Expected CCPort '9999', got '%s'", loadedConfig.CCPort)
	}
}

func TestSaveAndLoadConfigJSON(t *testing.T) {
	// Initialize RuntimeConfig
	live.RuntimeConfig = &def.Config{
		CCAddress:            "5.6.7.8",
		CCPort:               "5678",
		AgentSocksServerPort: "9090",
		Password:             "another_secret",
	}

	// Mock EmpConfigFile
	tmpFile, err := os.CreateTemp("", "emp3r0r_save_test_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	live.EmpConfigFile = tmpFile.Name()

	// Save config
	err = SaveConfigJSON()
	if err != nil {
		t.Fatalf("SaveConfigJSON failed: %v", err)
	}

	// Read the file content to check format (should be snake_case)
	content, err := os.ReadFile(live.EmpConfigFile)
	if err != nil {
		t.Fatalf("Failed to read saved config: %v", err)
	}

	// Check if keys are snake_case
	var raw map[string]interface{}
	err = json.Unmarshal(content, &raw)
	if err != nil {
		t.Fatalf("Failed to unmarshal saved JSON: %v", err)
	}

	if _, ok := raw["cc_address"]; !ok {
		t.Errorf("Saved JSON does not contain 'cc_address' key. Content: %s", string(content))
	}
	if _, ok := raw["CCAddress"]; ok {
		t.Errorf("Saved JSON contains 'CCAddress' key (should be snake_case). Content: %s", string(content))
	}
}
