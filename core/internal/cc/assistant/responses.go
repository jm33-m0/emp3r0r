package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// The Responses API is a different wire format from chat completions: system
// text goes in "instructions", calls and results are typed input items, and
// tool definitions are flat. Supporting it lets the assistant use providers
// that only expose /responses.

type responsesRequest struct {
	Model           string          `json:"model"`
	Instructions    string          `json:"instructions,omitempty"`
	Input           []any           `json:"input"`
	Tools           []responsesTool `json:"tools,omitempty"`
	ToolChoice      string          `json:"tool_choice,omitempty"`
	MaxOutputTokens int             `json:"max_output_tokens"`
	Store           bool            `json:"store"`
	Stream          bool            `json:"stream,omitempty"`
}

type responsesTool struct {
	Type        string         `json:"type"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type responsesResponse struct {
	Output     []responsesItem `json:"output"`
	OutputText string          `json:"output_text"`
	Error      *struct {
		Message string `json:"message"`
	} `json:"error"`
}

type responsesItem struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	CallID    string `json:"call_id"`
	Role      string `json:"role"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
	Content   []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

func (p *HTTPProvider) responsesChat(ctx context.Context, messages []Message, tools []ToolDef, toolChoice string, onDelta func(string)) (Message, error) {
	if p.cfg.Stream && onDelta != nil {
		return p.responsesStream(ctx, messages, tools, toolChoice, onDelta)
	}
	instructions, input := toResponsesInput(messages)
	payload := responsesRequest{
		Model:           p.cfg.Model,
		Instructions:    instructions,
		Input:           input,
		ToolChoice:      toolChoice,
		MaxOutputTokens: p.cfg.MaxTokens,
		Store:           false,
	}
	for _, tool := range tools {
		payload.Tools = append(payload.Tools, responsesTool{
			Type:        "function",
			Name:        tool.Function.Name,
			Description: tool.Function.Description,
			Parameters:  tool.Function.Parameters,
		})
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

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return Message{}, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Message{}, fmt.Errorf("provider returned %s: %s", resp.Status, snippet(raw, 1024))
	}

	var out responsesResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return Message{}, fmt.Errorf("decode response: %w", err)
	}
	if out.Error != nil && out.Error.Message != "" {
		return Message{}, fmt.Errorf("provider: %s", out.Error.Message)
	}
	if len(out.Output) == 0 && out.OutputText == "" {
		return Message{}, fmt.Errorf("provider returned no output")
	}
	return fromResponses(out), nil
}

// toResponsesInput converts the harness's chat-style history into Responses
// input items. Assistant tool calls and their outputs stay adjacent so a
// stateless replay preserves the pairing.
func toResponsesInput(messages []Message) (string, []any) {
	instructions := ""
	input := make([]any, 0, len(messages))
	for _, m := range messages {
		switch m.Role {
		case "system":
			if instructions != "" {
				instructions += "\n\n"
			}
			instructions += m.Content
		case "user":
			input = append(input, map[string]any{
				"role":    "user",
				"content": []any{map[string]any{"type": "input_text", "text": m.Content}},
			})
		case "assistant":
			if m.Content != "" {
				input = append(input, map[string]any{"role": "assistant", "content": m.Content})
			}
			for _, call := range m.ToolCalls {
				input = append(input, map[string]any{
					"type":      "function_call",
					"call_id":   call.ID,
					"name":      call.Function.Name,
					"arguments": call.Function.Arguments,
				})
			}
		case "tool":
			input = append(input, map[string]any{
				"type":    "function_call_output",
				"call_id": m.ToolCallID,
				"output":  m.Content,
			})
		}
	}
	return instructions, input
}

func fromResponses(resp responsesResponse) Message {
	out := Message{Role: "assistant"}
	var text []string
	for _, item := range resp.Output {
		switch item.Type {
		case "message":
			for _, c := range item.Content {
				if c.Type == "output_text" || c.Type == "text" {
					text = append(text, c.Text)
				}
			}
		case "function_call":
			callID := item.CallID
			if callID == "" {
				callID = item.ID
			}
			out.ToolCalls = append(out.ToolCalls, ToolCall{
				ID:   callID,
				Type: "function",
				Function: ToolCallFunction{
					Name:      item.Name,
					Arguments: item.Arguments,
				},
			})
		}
	}
	out.Content = joinText(text)
	if out.Content == "" {
		out.Content = resp.OutputText
	}
	return out
}

func joinText(parts []string) string {
	out := ""
	for _, part := range parts {
		if part == "" {
			continue
		}
		if out != "" {
			out += "\n"
		}
		out += part
	}
	return out
}
