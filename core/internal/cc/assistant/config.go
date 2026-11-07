// Package assistant implements the operator-side assistant: a small
// tool-calling loop over an OpenAI-compatible chat endpoint, plus the tool
// registry it reads. It runs in the operator process, so it can read the
// module registry, the active target, and the operator's cached command
// results without new trust boundaries. It is read-only: it can review a
// command but never executes one.
package assistant

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

const (
	// ConfigFileName is the operator workspace file that configures the
	// assistant.
	ConfigFileName = "assistant.json"

	// DefaultBaseURL points at a local OpenAI-compatible server (Ollama,
	// vLLM, llama.cpp). Non-loopback endpoints require allow_remote.
	DefaultBaseURL = "http://127.0.0.1:11434/v1"
	// DefaultModel is a local model with reliable tool calling.
	DefaultModel = "qwen2.5:32b"

	// API chat selects /chat/completions; API responses selects /responses.
	APIChat      = "chat"
	APIResponses = "responses"

	defaultMaxToolRounds  = 8
	defaultTimeoutSeconds = 180
	defaultMaxTokens      = 4096
	defaultMaxResultBytes = 4 << 20
	defaultHistory        = 24
)

// Config is the on-disk assistant configuration.
type Config struct {
	BaseURL               string `json:"base_url"`
	Model                 string `json:"model"`
	API                   string `json:"api"`
	APIKey                string `json:"api_key"`
	APIKeyEnv             string `json:"api_key_env"`
	AllowRemote           bool   `json:"allow_remote"`
	Stream                bool   `json:"stream"`
	MaxToolRounds         int    `json:"max_tool_rounds"`
	RequestTimeoutSeconds int    `json:"request_timeout_seconds"`
	MaxTokens             int    `json:"max_tokens"`
	MaxResultBytes        int64  `json:"max_result_bytes"`
	HistoryMessages       int    `json:"history_messages"`
}

// DefaultConfig returns the loopback defaults. A missing config file is not an
// error: the assistant starts against a local server and the first request
// fails with a clear connection error if nothing is listening.
func DefaultConfig() Config {
	return Config{
		BaseURL:               DefaultBaseURL,
		Model:                 DefaultModel,
		API:                   APIChat,
		Stream:                true,
		MaxToolRounds:         defaultMaxToolRounds,
		RequestTimeoutSeconds: defaultTimeoutSeconds,
		MaxTokens:             defaultMaxTokens,
		MaxResultBytes:        defaultMaxResultBytes,
		HistoryMessages:       defaultHistory,
	}
}

// ConfigPath returns the assistant config path in the operator workspace.
func ConfigPath() string {
	return filepath.Join(live.EmpWorkSpace, ConfigFileName)
}

// LoadConfig reads path, keeping defaults for absent fields.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Validate rejects configurations that could send target data off-host
// without an explicit opt-in, or that would make the tool loop unbounded.
func (c Config) Validate() error {
	if strings.TrimSpace(c.BaseURL) == "" {
		return fmt.Errorf("base_url is empty")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return fmt.Errorf("base_url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("base_url must use http or https")
	}
	if u.Host == "" {
		return fmt.Errorf("base_url has no host")
	}
	if u.User != nil {
		return fmt.Errorf("base_url must not embed credentials; use api_key or api_key_env")
	}
	if !c.AllowRemote && !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("base_url %q is not loopback; set allow_remote to send target data to it", u.Hostname())
	}
	if strings.TrimSpace(c.Model) == "" {
		return fmt.Errorf("model is empty")
	}
	if name := strings.TrimSpace(c.APIKeyEnv); name != "" && !validEnvName(name) {
		return fmt.Errorf("api_key_env must name an environment variable; use api_key for an inline key")
	}
	switch c.API {
	case APIChat, APIResponses:
	default:
		return fmt.Errorf("api must be %q or %q", APIChat, APIResponses)
	}
	if c.MaxToolRounds < 1 || c.MaxToolRounds > 32 {
		return fmt.Errorf("max_tool_rounds must be between 1 and 32")
	}
	if c.RequestTimeoutSeconds < 1 || c.RequestTimeoutSeconds > 600 {
		return fmt.Errorf("request_timeout_seconds must be between 1 and 600")
	}
	if c.MaxTokens < 1 || c.MaxTokens > 32768 {
		return fmt.Errorf("max_tokens must be between 1 and 32768")
	}
	if c.MaxResultBytes < 1024 || c.MaxResultBytes > 16<<20 {
		return fmt.Errorf("max_result_bytes must be between 1024 and 16777216")
	}
	if c.HistoryMessages < 0 || c.HistoryMessages > 200 {
		return fmt.Errorf("history_messages must be between 0 and 200")
	}
	return nil
}

// Endpoint returns the URL derived from BaseURL for the selected API.
func (c Config) Endpoint() string {
	base := strings.TrimRight(c.BaseURL, "/")
	if c.API == APIResponses {
		return base + "/responses"
	}
	return base + "/chat/completions"
}

// Timeout returns the per-request deadline.
func (c Config) Timeout() time.Duration {
	return time.Duration(c.RequestTimeoutSeconds) * time.Second
}

// ResolveAPIKey returns the bearer token. api_key_env names an environment
// variable and takes precedence; api_key is an inline fallback for a 0600
// config file; OPENAI_API_KEY is the final fallback.
func (c Config) ResolveAPIKey() (string, error) {
	if name := strings.TrimSpace(c.APIKeyEnv); name != "" {
		key := strings.TrimSpace(os.Getenv(name))
		if key == "" {
			return "", fmt.Errorf("api_key_env %q is not set", name)
		}
		return key, nil
	}
	if key := strings.TrimSpace(c.APIKey); key != "" {
		return key, nil
	}
	return strings.TrimSpace(os.Getenv("OPENAI_API_KEY")), nil
}

func validEnvName(name string) bool {
	for i, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r == '_':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return name != ""
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
