package modules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadModConfig(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir, err := os.MkdirTemp("", "emp3r0r-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Define a sample JSON config
	jsonConfig := `{
		"name": "test_module",
		"build": "go build",
		"author": "tester",
		"date": "2023-10-27",
		"comment": "A test module",
		"is_local": true,
		"platform": "Linux",
		"path": "/tmp/test_module",
		"fileless": false,
		"agent_config": {
			"exec": "test_exec",
			"files": ["file1", "file2"],
			"in_memory": true,
			"type": "go",
			"is_interactive": false
		},
		"options": {
			"option1": {
				"name": "option1",
				"desc": "Description 1",
				"val": "value1",
				"vals": ["value1", "value2"]
			}
		}
	}`

	// Write the config to a file
	configFile := filepath.Join(tmpDir, "config.json")
	err = os.WriteFile(configFile, []byte(jsonConfig), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Call the function to test
	config, err := readModCondig(configFile)
	if err != nil {
		t.Fatalf("readModCondig failed: %v", err)
	}

	// Verify the results
	if config.Name != "test_module" {
		t.Errorf("Expected Name 'test_module', got '%s'", config.Name)
	}
	if config.Build != "go build" {
		t.Errorf("Expected Build 'go build', got '%s'", config.Build)
	}
	if config.Author != "tester" {
		t.Errorf("Expected Author 'tester', got '%s'", config.Author)
	}
	if !config.IsLocal {
		t.Errorf("Expected IsLocal true, got false")
	}
	if config.AgentConfig.Exec != "test_exec" {
		t.Errorf("Expected AgentConfig.Exec 'test_exec', got '%s'", config.AgentConfig.Exec)
	}
	if len(config.AgentConfig.Files) != 2 {
		t.Errorf("Expected 2 files, got %d", len(config.AgentConfig.Files))
	}
	if !config.AgentConfig.InMemory {
		t.Errorf("Expected AgentConfig.InMemory true, got false")
	}

	opt, ok := config.Options["option1"]
	if !ok {
		t.Fatalf("Expected option1 to exist")
	}
	if opt.Val != "value1" {
		t.Errorf("Expected option1 value 'value1', got '%s'", opt.Val)
	}
}

func TestReadModConfigPartial(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir, err := os.MkdirTemp("", "emp3r0r-test-partial")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Define a sample JSON config with missing fields
	jsonConfig := `{
		"name": "test_module_partial"
	}`

	// Write the config to a file
	configFile := filepath.Join(tmpDir, "config.json")
	err = os.WriteFile(configFile, []byte(jsonConfig), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Call the function to test
	config, err := readModCondig(configFile)
	if err != nil {
		t.Fatalf("readModCondig failed: %v", err)
	}

	// Verify the results
	if config.Name != "test_module_partial" {
		t.Errorf("Expected Name 'test_module_partial', got '%s'", config.Name)
	}
	if config.Build != "" {
		t.Errorf("Expected Build '', got '%s'", config.Build)
	}
	if config.IsLocal {
		t.Errorf("Expected IsLocal false, got true")
	}
}
