package assistant

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigRejectsRemoteByDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BaseURL = "https://api.example.com/v1"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected a non-loopback endpoint to be rejected without allow_remote")
	}
	cfg.AllowRemote = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("allow_remote should permit a remote endpoint: %v", err)
	}
}

func TestConfigEndpointByAPI(t *testing.T) {
	cfg := DefaultConfig()
	if got := cfg.Endpoint(); got != DefaultBaseURL+"/chat/completions" {
		t.Fatalf("chat endpoint = %q", got)
	}
	cfg.API = APIResponses
	if got := cfg.Endpoint(); got != DefaultBaseURL+"/responses" {
		t.Fatalf("responses endpoint = %q", got)
	}
}

func TestLoadConfigMissingUsesDefaults(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("missing config: %v", err)
	}
	if cfg.Model != DefaultModel || cfg.API != APIChat {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadConfigRejectsUnknownAPI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assistant.json")
	if err := os.WriteFile(path, []byte(`{"api":"grpc"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected an unknown api mode to fail validation")
	}
}

func TestLoadConfigRejectsRemoteWithoutOptIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assistant.json")
	if err := os.WriteFile(path, []byte(`{"base_url":"https://api.example.com/v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected a remote endpoint to fail validation")
	}
}

func TestResolveAPIKeyInline(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "  sk-inline  "
	key, err := cfg.ResolveAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if key != "sk-inline" {
		t.Fatalf("key = %q", key)
	}
}

func TestResolveAPIKeyMissingEnv(t *testing.T) {
	const name = "ASSISTANT_TEST_KEY_NOT_SET"
	t.Setenv(name, "")
	cfg := DefaultConfig()
	cfg.APIKeyEnv = name
	if _, err := cfg.ResolveAPIKey(); err == nil {
		t.Fatal("expected an error for an unset api_key_env")
	}
}

func TestConfigRejectsKeyInEnvName(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeyEnv = "sk-850bb029bf098a8c4b304f26e6ea872412cc9b271461e165cbe40f7f8768dd0d"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected a key in api_key_env to be rejected")
	}
}
