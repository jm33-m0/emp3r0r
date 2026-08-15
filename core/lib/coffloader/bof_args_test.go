package coffloader

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type modConfig struct {
	Name        string `json:"name"`
	AgentConfig struct {
		Type string `json:"type"`
	} `json:"agent_config"`
	Parameters []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"parameters"`
}

func getModulesRoot() string {
	_, b, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(b))), "modules")
}

func typeToWireToken(t string) string {
	// Canonical single-char tokens are case-sensitive: z is narrow, Z is wide,
	// s is short.
	switch t {
	case "z":
		return "z"
	case "Z":
		return "Z"
	case "i":
		return "i"
	case "s":
		return "s"
	case "b":
		return "b"
	}

	switch strings.ToLower(t) {
	case "cstr", "string", "str", "lpstr":
		return "z"
	case "wstr", "wstring", "lpwstr", "w":
		return "Z"
	case "int", "dword", "uint32", "uint", "int32", "port", "bool":
		return "i"
	case "short", "word", "int16":
		return "s"
	case "binary", "base64":
		return "b"
	default:
		return ""
	}
}

func TestCOFFArgParsingAllModules(t *testing.T) {
	modulesRoot := getModulesRoot()
	if _, err := os.Stat(modulesRoot); os.IsNotExist(err) {
		t.Skipf("modules directory not found at %s", modulesRoot)
	}

	dirs, err := os.ReadDir(modulesRoot)
	if err != nil {
		t.Fatalf("failed to read modules directory: %v", err)
	}

	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		configPath := filepath.Join(modulesRoot, dir.Name(), "config.json")
		data, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}

		var configs []modConfig
		if err := json.Unmarshal(data, &configs); err != nil {
			continue
		}

		t.Run(dir.Name(), func(t *testing.T) {
			for _, config := range configs {
				if !strings.EqualFold(config.AgentConfig.Type, "coff") {
					continue
				}

				var coffArgs []CoffArg
				for _, param := range config.Parameters {
					wireToken := typeToWireToken(param.Type)
					if wireToken == "" {
						t.Errorf("module %s (COFF) has parameter '%s' with unsupported type '%s'", config.Name, param.Name, param.Type)
						continue
					}

					var dummyVal any = "dummy"
					if wireToken == "i" || wireToken == "s" {
						dummyVal = 1
					}
					coffArgs = append(coffArgs, CoffArg{
						WireType: wireToken,
						Value:    dummyVal,
					})
				}

				if len(coffArgs) > 0 {
					packed, err := PackCoffArgs(coffArgs)
					if err != nil {
						t.Errorf("PackCoffArgs failed for %s: %v", config.Name, err)
					}
					for _, arg := range packed {
						if len(arg) == 0 {
							t.Errorf("Packed arg is empty for %s", config.Name)
						}
					}
				}
			}
		})
	}
}
