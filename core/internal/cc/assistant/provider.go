package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Message is one chat message in the provider's wire format.
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// ToolCall is a model-requested function call.
type ToolCall struct {
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	Function ToolCallFunction `json:"function"`
}

// ToolCallFunction carries the function name and its JSON arguments.
type ToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ToolDef is the JSON schema advertised to the model.
type ToolDef struct {
	Type     string      `json:"type"`
	Function FunctionDef `json:"function"`
}

// FunctionDef describes one callable tool.
type FunctionDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type chatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Tools       []ToolDef `json:"tools,omitempty"`
	ToolChoice  string    `json:"tool_choice,omitempty"`
	Temperature float64   `json:"temperature"`
	MaxTokens   int       `json:"max_tokens"`
	Stream      bool      `json:"stream,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message      Message `json:"message"`
		FinishReason string  `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Provider is the subset of an OpenAI-compatible chat endpoint the harness
// needs. Tests substitute a fake implementation.
type Provider interface {
	Chat(ctx context.Context, messages []Message, tools []ToolDef, toolChoice string, onDelta func(string)) (Message, error)
}

// HTTPProvider calls a remote OpenAI-compatible /chat/completions endpoint.
type HTTPProvider struct {
	cfg    Config
	client *http.Client
}

// NewHTTPProvider returns a provider for cfg.
func NewHTTPProvider(cfg Config) *HTTPProvider {
	return &HTTPProvider{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout(),
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				if !cfg.AllowRemote && !isLoopbackHost(req.URL.Hostname()) {
					return fmt.Errorf("redirect to non-loopback host %q refused without allow_remote", req.URL.Hostname())
				}
				return http.ErrUseLastResponse
			},
		},
	}
}

// Chat sends one completion request. Tool calls are returned unresolved; the
// harness decides whether to execute them.
func (p *HTTPProvider) Chat(ctx context.Context, messages []Message, tools []ToolDef, toolChoice string, onDelta func(string)) (Message, error) {
	if p.cfg.API == APIResponses {
		return p.responsesChat(ctx, messages, tools, toolChoice, onDelta)
	}
	if p.cfg.Stream && onDelta != nil {
		return p.chatCompletionsStream(ctx, messages, tools, toolChoice, onDelta)
	}
	return p.chatCompletions(ctx, messages, tools, toolChoice)
}

func (p *HTTPProvider) chatCompletions(ctx context.Context, messages []Message, tools []ToolDef, toolChoice string) (Message, error) {
	payload := chatRequest{
		Model:       p.cfg.Model,
		Messages:    messages,
		Tools:       tools,
		ToolChoice:  toolChoice,
		Temperature: 0.2,
		MaxTokens:   p.cfg.MaxTokens,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Message{}, fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.Endpoint(), bytes.NewReader(body))
	if err != nil {
		return Message{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	key, err := p.cfg.ResolveAPIKey()
	if err != nil {
		return Message{}, err
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return Message{}, fmt.Errorf("contact %s: %w", p.cfg.Endpoint(), err)
	}
	defer resp.Body.Close()

	// A provider response is small compared with a job log; bound it so a
	// hostile or broken endpoint cannot exhaust console memory.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return Message{}, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Message{}, fmt.Errorf("provider returned %s: %s", resp.Status, snippet(raw, 1024))
	}

	var out chatResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return Message{}, fmt.Errorf("decode response: %w", err)
	}
	if out.Error != nil && strings.TrimSpace(out.Error.Message) != "" {
		return Message{}, fmt.Errorf("provider: %s", out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return Message{}, fmt.Errorf("provider returned no choices")
	}
	return out.Choices[0].Message, nil
}

func snippet(b []byte, limit int) string {
	s := strings.TrimSpace(string(b))
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}
