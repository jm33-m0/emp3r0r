package def

import (
	"encoding/json"
	"testing"
)

func TestReadJSONConfig(t *testing.T) {
	// 1. Test with valid JSON
	validConfig := Config{
		CCAddress:            "127.0.0.1:8080",
		CCHost:               "localhost",
		CCPort:               "8080",
		AgentSocksServerPort: "1080",
		UtilsPath:            "/tmp/emp3r0r",
	}
	jsonData, err := json.Marshal(validConfig)
	if err != nil {
		t.Fatalf("Failed to marshal valid config: %v", err)
	}

	var config Config
	err = ReadJSONConfig(jsonData, &config)
	if err != nil {
		t.Errorf("ReadJSONConfig failed with valid JSON: %v", err)
	}

	// Check derived fields
	expectedReverseProxyPort := "1081" // 1080 + 1
	if config.Bring2CCReverseProxyPort != expectedReverseProxyPort {
		t.Errorf("Expected Bring2CCReverseProxyPort to be %s, got %s", expectedReverseProxyPort, config.Bring2CCReverseProxyPort)
	}

	expectedCCAddress := "https://127.0.0.1:8080"
	if CCAddress != expectedCCAddress {
		t.Errorf("Expected CCAddress global to be %s, got %s", expectedCCAddress, CCAddress)
	}

	expectedDefaultShell := "/tmp/emp3r0r/bash"
	if DefaultShell != expectedDefaultShell {
		t.Errorf("Expected DefaultShell global to be %s, got %s", expectedDefaultShell, DefaultShell)
	}

	// 2. Test with invalid JSON (malformed)
	invalidJSON := []byte(`{ "CCAddress": "127.0.0.1", `) // Missing closing brace
	err = ReadJSONConfig(invalidJSON, &config)
	if err == nil {
		t.Error("ReadJSONConfig should have failed with invalid JSON")
	}

	// 3. Test with invalid AgentSocksServerPort (not a number)
	invalidPortConfig := Config{
		AgentSocksServerPort: "invalid-port",
	}
	invalidPortJSON, _ := json.Marshal(invalidPortConfig)
	err = ReadJSONConfig(invalidPortJSON, &config)
	if err == nil {
		t.Error("ReadJSONConfig should have failed with invalid AgentSocksServerPort")
	}
}
