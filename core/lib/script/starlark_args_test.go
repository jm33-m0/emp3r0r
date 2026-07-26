package script

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type starlarkModConfig struct {
	Name        string `json:"name"`
	AgentConfig struct {
		Type string `json:"type"`
	} `json:"agent_config"`
	Parameters []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"parameters"`
}

func TestStarlarkArgParsing(t *testing.T) {
	_, b, _, _ := runtime.Caller(0)
	modulesRoot := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(b))), "modules")
	configPath := filepath.Join(modulesRoot, "starlark_SA/config.json")

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Skipf("config %s not found", configPath)
	}

	var configs []starlarkModConfig
	if err := json.Unmarshal(data, &configs); err != nil {
		t.Fatalf("failed to parse %s: %v", configPath, err)
	}

	found := false
	for _, config := range configs {
		if strings.EqualFold(config.AgentConfig.Type, "starlark") {
			found = true
			if config.Name == "" {
				t.Errorf("Starlark module config has empty name in %s", configPath)
			}
		}
	}

	if !found {
		t.Errorf("No Starlark modules found in %s", configPath)
	}
}
