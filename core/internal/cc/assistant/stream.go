package assistant

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

var errStreamDone = errors.New("stream done")

type toolAcc struct {
	id   string
	name string
	args string
}

type chatStreamChunk struct {
	Choices []struct {
		Delta struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				Index    int    `json:"index"`
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

type responsesEvent struct {
	Type     string             `json:"type"`
	Delta    string             `json:"delta"`
	Item     *responsesItem     `json:"item"`
	Response *responsesResponse `json:"response"`
	Error    *struct {
		Message string `json:"message"`
	} `json:"error"`
	Message string `json:"message"`
}

func (p *HTTPProvider) chatCompletionsStream(ctx context.Context, messages []Message, tools []ToolDef, toolChoice string, onDelta func(string)) (Message, error) {
	payload := chatRequest{
		Model:       p.cfg.Model,
		Messages:    messages,
		Tools:       tools,
		ToolChoice:  toolChoice,
		Temperature: 0.2,
		MaxTokens:   p.cfg.MaxTokens,
		Stream:      true,
	}
	resp, err := p.postJSON(ctx, payload)
	if err != nil {
		return Message{}, err
	}
	defer resp.Body.Close()

	if !isEventStream(resp) {
		return parseChatCompletion(resp.Body)
	}

	var content strings.Builder
	acc := make(map[int]*toolAcc)
	err = scanSSE(resp.Body, func(data []byte) error {
		if bytes.Equal(data, []byte("[DONE]")) {
			return errStreamDone
		}
		var chunk chatStreamChunk
		if err := json.Unmarshal(data, &chunk); err != nil {
			return fmt.Errorf("decode stream event: %w", err)
		}
		if chunk.Error != nil && chunk.Error.Message != "" {
			return fmt.Errorf("provider: %s", chunk.Error.Message)
		}
		for _, choice := range chunk.Choices {
			if choice.Delta.Content != "" {
				content.WriteString(choice.Delta.Content)
				onDelta(choice.Delta.Content)
			}
			for _, call := range choice.Delta.ToolCalls {
				entry := acc[call.Index]
				if entry == nil {
					entry = &toolAcc{}
					acc[call.Index] = entry
				}
				if call.ID != "" {
					entry.id = call.ID
				}
				entry.name += call.Function.Name
				entry.args += call.Function.Arguments
			}
		}
		return nil
	})
	if errors.Is(err, errStreamDone) {
		err = nil
	}
	if err != nil {
		return Message{}, err
	}
	return Message{
		Role:      "assistant",
		Content:   content.String(),
		ToolCalls: toolCallsFromAcc(acc),
	}, nil
}

func (p *HTTPProvider) responsesStream(ctx context.Context, messages []Message, tools []ToolDef, toolChoice string, onDelta func(string)) (Message, error) {
	instructions, input := toResponsesInput(messages)
	payload := responsesRequest{
		Model:           p.cfg.Model,
		Instructions:    instructions,
		Input:           input,
		ToolChoice:      toolChoice,
		MaxOutputTokens: p.cfg.MaxTokens,
		Store:           false,
		Stream:          true,
	}
	for _, tool := range tools {
		payload.Tools = append(payload.Tools, responsesTool{
			Type:        "function",
			Name:        tool.Function.Name,
			Description: tool.Function.Description,
			Parameters:  tool.Function.Parameters,
		})
	}

	resp, err := p.postJSON(ctx, payload)
	if err != nil {
		return Message{}, err
	}
	defer resp.Body.Close()

	if !isEventStream(resp) {
		var out responsesResponse
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		if readErr != nil {
			return Message{}, fmt.Errorf("read response: %w", readErr)
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return Message{}, fmt.Errorf("decode response: %w", err)
		}
		return fromResponses(out), nil
	}

	var content strings.Builder
	var calls []ToolCall
	var final *responsesResponse
	err = scanSSE(resp.Body, func(data []byte) error {
		if bytes.Equal(data, []byte("[DONE]")) {
			return errStreamDone
		}
		var event responsesEvent
		if err := json.Unmarshal(data, &event); err != nil {
			return fmt.Errorf("decode stream event: %w", err)
		}
		switch event.Type {
		case "response.output_text.delta":
			if event.Delta != "" {
				content.WriteString(event.Delta)
				onDelta(event.Delta)
			}
		case "response.output_item.done":
			if event.Item != nil && event.Item.Type == "function_call" {
				id := event.Item.CallID
				if id == "" {
					id = event.Item.ID
				}
				calls = append(calls, ToolCall{
					ID:   id,
					Type: "function",
					Function: ToolCallFunction{
						Name:      event.Item.Name,
						Arguments: event.Item.Arguments,
					},
				})
			}
		case "response.completed":
			if event.Response != nil {
				final = event.Response
			}
		case "response.failed":
			if event.Response != nil && event.Response.Error != nil {
				return fmt.Errorf("provider: %s", event.Response.Error.Message)
			}
			return fmt.Errorf("provider: response failed")
		case "error":
			if event.Error != nil && event.Error.Message != "" {
				return fmt.Errorf("provider: %s", event.Error.Message)
			}
			if event.Message != "" {
				return fmt.Errorf("provider: %s", event.Message)
			}
			return fmt.Errorf("provider stream error")
		}
		return nil
	})
	if errors.Is(err, errStreamDone) {
		err = nil
	}
	if err != nil {
		return Message{}, err
	}

	out := Message{Role: "assistant", Content: content.String(), ToolCalls: calls}
	if final != nil {
		parsed := fromResponses(*final)
		if parsed.Content != "" {
			out.Content = parsed.Content
		}
		if len(parsed.ToolCalls) > 0 {
			out.ToolCalls = parsed.ToolCalls
		}
	}
	return out, nil
}

func parseChatCompletion(r io.Reader) (Message, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 16<<20))
	if err != nil {
		return Message{}, fmt.Errorf("read response: %w", err)
	}
	var out chatResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return Message{}, fmt.Errorf("decode response: %w", err)
	}
	if out.Error != nil && out.Error.Message != "" {
		return Message{}, fmt.Errorf("provider: %s", out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return Message{}, fmt.Errorf("provider returned no choices")
	}
	return out.Choices[0].Message, nil
}

func (p *HTTPProvider) postJSON(ctx context.Context, payload any) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.Endpoint(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	key, err := p.cfg.ResolveAPIKey()
	if err != nil {
		return nil, err
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("contact %s: %w", p.cfg.Endpoint(), err)
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("provider returned %s: %s", resp.Status, snippet(raw, 1024))
	}
	return resp, nil
}

func isEventStream(resp *http.Response) bool {
	return strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")
}

// scanSSE yields one complete SSE data payload at a time. Multi-line data
// fields are joined per the SSE specification; comments and event/id lines are
// ignored.
func scanSSE(r io.Reader, fn func([]byte) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	var data []byte
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimPrefix(line, "data:")...)
			data = append(data, '\n')
			continue
		}
		if strings.TrimSpace(line) == "" && len(data) > 0 {
			payload := bytes.TrimSpace(data)
			data = nil
			if err := fn(payload); err != nil {
				return err
			}
		}
	}
	if len(data) > 0 {
		if err := fn(bytes.TrimSpace(data)); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func toolCallsFromAcc(acc map[int]*toolAcc) []ToolCall {
	if len(acc) == 0 {
		return nil
	}
	indexes := make([]int, 0, len(acc))
	for index := range acc {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	calls := make([]ToolCall, 0, len(indexes))
	for _, index := range indexes {
		entry := acc[index]
		id := entry.id
		if id == "" {
			id = fmt.Sprintf("call_%d", index)
		}
		calls = append(calls, ToolCall{
			ID:   id,
			Type: "function",
			Function: ToolCallFunction{
				Name:      entry.name,
				Arguments: entry.args,
			},
		})
	}
	return calls
}
