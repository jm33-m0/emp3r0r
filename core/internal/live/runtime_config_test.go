package live

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"strconv"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

func TestInitConfigFile(t *testing.T) {
	// Initialize RuntimeConfig if it's nil
	if RuntimeConfig == nil {
		RuntimeConfig = &def.Config{}
	}

	// Setup temp file for config
	tmpConfigFile, err := os.CreateTemp("", "emp3r0r.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpConfigFile.Name())
	tmpConfigFile.Close()

	// Save original EmpConfigFile and restore it after test
	originalEmpConfigFile := EmpConfigFile
	defer func() { EmpConfigFile = originalEmpConfigFile }()
	EmpConfigFile = tmpConfigFile.Name()

	// Setup temp file for CA Key
	tmpKeyFile, err := os.CreateTemp("", "ca-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpKeyFile.Name())

	// Generate a dummy CA key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privKeyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: privKeyBytes}
	if err := pem.Encode(tmpKeyFile, pemBlock); err != nil {
		t.Fatal(err)
	}
	tmpKeyFile.Close()

	// Save original CaKeyFile and restore it after test
	originalCaKeyFile := transport.CaKeyFile
	defer func() { transport.CaKeyFile = originalCaKeyFile }()
	transport.CaKeyFile = tmpKeyFile.Name()

	ccHost := "127.0.0.1"
	err = InitConfigFile(ccHost)
	if err != nil {
		t.Fatalf("InitConfigFile failed: %v", err)
	}

	// Verify fields
	if RuntimeConfig.CCAddress != ccHost {
		t.Errorf("Expected CCAddress %s, got %s", ccHost, RuntimeConfig.CCAddress)
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

	checkPort("CCPort", RuntimeConfig.CCPort)
	checkPort("AgentSocksServerPort", RuntimeConfig.AgentSocksServerPort)
	checkPort("SSHDShellPort", RuntimeConfig.SSHDShellPort)

	// Check if UUID is set
	if RuntimeConfig.AgentUUID == "" {
		t.Error("AgentUUID is empty")
	}

	// Check if SSHHostKey is generated
	if len(RuntimeConfig.SSHHostKey) == 0 {
		t.Error("SSHHostKey is empty")
	}
	
	// Check if AgentUUIDSig is set
	if RuntimeConfig.AgentUUIDSig == "" {
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
	originalEmpConfigFile := EmpConfigFile
	defer func() { EmpConfigFile = originalEmpConfigFile }()

	EmpConfigFile = tmpFile.Name()

	// Setup a dummy RuntimeConfig
	RuntimeConfig = &def.Config{
		CCAddress: "test.example.com",
		CCPort:    "9999",
	}

	// Test SaveConfigJSON
	err = SaveConfigJSON()
	if err != nil {
		t.Fatalf("SaveConfigJSON failed: %v", err)
	}

	// Read back the file
	data, err := os.ReadFile(EmpConfigFile)
	if err != nil {
		t.Fatalf("Failed to read saved config file: %v", err)
	}

	var loadedConfig def.Config
	err = json.Unmarshal(data, &loadedConfig)
	if err != nil {
		t.Fatalf("Failed to unmarshal saved config: %v", err)
	}

	if loadedConfig.CCAddress != "test.example.com" {
		t.Errorf("Loaded config mismatch. Expected CCAddress 'test.example.com', got '%s'", loadedConfig.CCAddress)
	}
	if loadedConfig.CCPort != "9999" {
		t.Errorf("Loaded config mismatch. Expected CCPort '9999', got '%s'", loadedConfig.CCPort)
	}
}
