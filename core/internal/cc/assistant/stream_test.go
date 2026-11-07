package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func sse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
}

func TestChatStreamText(t *testing.T) {
	var request map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		sse(w)
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"He\"}}]}\n\n")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"llo\"}}]}\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL
	provider := NewHTTPProvider(cfg)
	var deltas strings.Builder
	msg, err := provider.Chat(context.Background(), []Message{{Role: "user", Content: "hi"}}, nil, "", func(d string) {
		deltas.WriteString(d)
	})
	if err != nil {
		t.Fatal(err)
	}
	if deltas.String() != "Hello" || msg.Content != "Hello" {
		t.Fatalf("deltas=%q content=%q", deltas.String(), msg.Content)
	}
	if request["stream"] != true {
		t.Fatalf("stream not requested: %#v", request["stream"])
	}
}

func TestChatStreamToolCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sse(w)
		chunks := []map[string]any{
			{"choices": []any{map[string]any{"delta": map[string]any{"tool_calls": []any{
				map[string]any{
					"index": 0, "id": "call-1", "type": "function",
					"function": map[string]any{"name": "list_modules", "arguments": "{\"query\":"},
				},
			}}}}},
			{"choices": []any{map[string]any{"delta": map[string]any{"tool_calls": []any{
				map[string]any{
					"index":    0,
					"function": map[string]any{"arguments": "\"ldap\"}"},
				},
			}}}}},
		}
		for _, chunk := range chunks {
			b, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\n", b)
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL
	provider := NewHTTPProvider(cfg)
	msg, err := provider.Chat(context.Background(), []Message{{Role: "user", Content: "hi"}}, nil, "", func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.ToolCalls) != 1 {
		t.Fatalf("tool calls = %d", len(msg.ToolCalls))
	}
	if msg.ToolCalls[0].Function.Arguments != `{"query":"ldap"}` {
		t.Fatalf("arguments = %q", msg.ToolCalls[0].Function.Arguments)
	}
}

func TestResponsesStreamText(t *testing.T) {
	var request map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		sse(w)
		fmt.Fprint(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"He\"}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"llo\"}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"Hello\"}]}]}}\n\n")
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL
	cfg.API = APIResponses
	provider := NewHTTPProvider(cfg)
	var deltas strings.Builder
	msg, err := provider.Chat(context.Background(), []Message{{Role: "user", Content: "hi"}}, nil, "", func(d string) {
		deltas.WriteString(d)
	})
	if err != nil {
		t.Fatal(err)
	}
	if deltas.String() != "Hello" || msg.Content != "Hello" {
		t.Fatalf("deltas=%q content=%q", deltas.String(), msg.Content)
	}
	if request["stream"] != true {
		t.Fatalf("stream not requested: %#v", request["stream"])
	}
}

func TestResponsesStreamToolCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sse(w)
		fmt.Fprint(w, "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"call-1\",\"name\":\"list_modules\",\"arguments\":\"{}\"}}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"response.completed\",\"response\":{\"output\":[]}}\n\n")
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL
	cfg.API = APIResponses
	provider := NewHTTPProvider(cfg)
	msg, err := provider.Chat(context.Background(), []Message{{Role: "user", Content: "hi"}}, nil, "", func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.ToolCalls) != 1 {
		t.Fatalf("tool calls = %d", len(msg.ToolCalls))
	}
	if msg.ToolCalls[0].ID != "call-1" || msg.ToolCalls[0].Function.Name != "list_modules" {
		t.Fatalf("tool call = %+v", msg.ToolCalls[0])
	}
}

func TestResponsesStreamFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sse(w)
		fmt.Fprint(w, "data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"message\":\"nope\"}}}\n\n")
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL
	cfg.API = APIResponses
	provider := NewHTTPProvider(cfg)
	_, err := provider.Chat(context.Background(), []Message{{Role: "user", Content: "hi"}}, nil, "", func(string) {})
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("err = %v", err)
	}
}

func TestStreamFallsBackToJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"fallback"}}]}`)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL
	provider := NewHTTPProvider(cfg)
	msg, err := provider.Chat(context.Background(), []Message{{Role: "user", Content: "hi"}}, nil, "", func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if msg.Content != "fallback" {
		t.Fatalf("content = %q", msg.Content)
	}
}
