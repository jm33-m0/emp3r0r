package assistant

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResponsesProviderParsesText(t *testing.T) {
	var request map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"output":[{"type":"message","content":[{"type":"output_text","text":"hello"}]}]}`)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL
	cfg.API = APIResponses
	cfg.Model = "test-model"
	provider := NewHTTPProvider(cfg)
	msg, err := provider.Chat(context.Background(), []Message{
		{Role: "system", Content: "system text"},
		{Role: "user", Content: "hi"},
	}, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Content != "hello" {
		t.Fatalf("content = %q", msg.Content)
	}
	if got, _ := request["instructions"].(string); got != "system text" {
		t.Fatalf("instructions = %q", got)
	}
	input, ok := request["input"].([]any)
	if !ok || len(input) != 1 {
		t.Fatalf("input = %#v", request["input"])
	}
}

func TestResponsesProviderParsesFunctionCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"output":[{"type":"function_call","call_id":"call-1","name":"list_modules","arguments":"{\"query\":\"ldap\"}"}]}`)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL
	cfg.API = APIResponses
	cfg.Model = "test-model"
	provider := NewHTTPProvider(cfg)
	msg, err := provider.Chat(context.Background(), []Message{{Role: "user", Content: "hi"}}, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.ToolCalls) != 1 {
		t.Fatalf("tool calls = %d", len(msg.ToolCalls))
	}
	call := msg.ToolCalls[0]
	if call.ID != "call-1" || call.Function.Name != "list_modules" {
		t.Fatalf("tool call = %+v", call)
	}
}

func TestToResponsesInputPairsCallsAndOutputs(t *testing.T) {
	instructions, input := toResponsesInput([]Message{
		{Role: "system", Content: "sys"},
		{Role: "user", Content: "q"},
		{Role: "assistant", ToolCalls: []ToolCall{{
			ID: "c1", Type: "function",
			Function: ToolCallFunction{Name: "list_modules", Arguments: "{}"},
		}}},
		{Role: "tool", ToolCallID: "c1", Content: `{"modules":[]}`},
	})
	if instructions != "sys" {
		t.Fatalf("instructions = %q", instructions)
	}
	if len(input) != 3 {
		t.Fatalf("input items = %d", len(input))
	}
	call, _ := input[1].(map[string]any)
	if call["type"] != "function_call" || call["call_id"] != "c1" {
		t.Fatalf("call item = %#v", call)
	}
	result, _ := input[2].(map[string]any)
	if result["type"] != "function_call_output" || result["call_id"] != "c1" {
		t.Fatalf("result item = %#v", result)
	}
}
