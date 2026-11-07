package assistant

import (
	"context"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

type fakeProvider struct {
	replies  []Message
	calls    int
	requests [][]Message
	tools    []int
}

func (f *fakeProvider) Chat(_ context.Context, messages []Message, tools []ToolDef, _ string, onDelta func(string)) (Message, error) {
	f.requests = append(f.requests, append([]Message(nil), messages...))
	f.tools = append(f.tools, len(tools))
	if len(tools) == 0 {
		f.calls++
		return Message{Role: "assistant", Content: "final"}, nil
	}
	reply := Message{Role: "assistant"}
	switch {
	case f.calls < len(f.replies):
		reply = f.replies[f.calls]
	case len(f.replies) > 0:
		// Keep returning the same tool call until the harness spends its
		// budget; the final no-tools request then returns "final".
		reply = f.replies[len(f.replies)-1]
	default:
		reply.Content = "final"
	}
	f.calls++
	if reply.Content != "" && onDelta != nil {
		onDelta(reply.Content)
	}
	return reply, nil
}

func TestHarnessRunsToolThenAnswers(t *testing.T) {
	provider := &fakeProvider{replies: []Message{
		{
			Role: "assistant",
			ToolCalls: []ToolCall{{
				ID:       "call-1",
				Type:     "function",
				Function: ToolCallFunction{Name: "list_modules", Arguments: "{}"},
			}},
		},
		{Role: "assistant", Content: "done"},
	}}
	cfg := DefaultConfig()
	cfg.MaxToolRounds = 4
	h, err := NewWithProvider(cfg, provider)
	if err != nil {
		t.Fatal(err)
	}
	var session Session
	text, err := h.Ask(context.Background(), &session, &def.Emp3r0rAgent{Tag: "agent-1"}, "which modules?", nil)
	if err != nil {
		t.Fatal(err)
	}
	if text != "done" {
		t.Fatalf("answer = %q", text)
	}
	if provider.calls != 2 {
		t.Fatalf("provider calls = %d", provider.calls)
	}
	if provider.tools[0] != 8 || provider.tools[1] != 8 {
		t.Fatalf("tool counts = %v", provider.tools)
	}
	foundToolResult := false
	for _, msg := range provider.requests[1] {
		if msg.Role == "tool" && msg.ToolCallID == "call-1" {
			foundToolResult = true
		}
	}
	if !foundToolResult {
		t.Fatal("second request did not carry the tool result")
	}
}

func TestHarnessStopsAtToolBudget(t *testing.T) {
	provider := &fakeProvider{replies: []Message{
		{Role: "assistant", ToolCalls: []ToolCall{{
			ID: "call-1", Type: "function",
			Function: ToolCallFunction{Name: "list_agents", Arguments: "{}"},
		}}},
	}}
	cfg := DefaultConfig()
	cfg.MaxToolRounds = 2
	h, err := NewWithProvider(cfg, provider)
	if err != nil {
		t.Fatal(err)
	}
	var session Session
	text, err := h.Ask(context.Background(), &session, nil, "loop", nil)
	if err != nil {
		t.Fatal(err)
	}
	if text != "final" {
		t.Fatalf("answer = %q", text)
	}
	if provider.calls != 3 {
		t.Fatalf("expected two tool rounds plus one final call, got %d", provider.calls)
	}
}

func TestHarnessResetsOnTargetSwitch(t *testing.T) {
	provider := &fakeProvider{}
	cfg := DefaultConfig()
	h, err := NewWithProvider(cfg, provider)
	if err != nil {
		t.Fatal(err)
	}
	var session Session
	if _, err := h.Ask(context.Background(), &session, &def.Emp3r0rAgent{Tag: "a"}, "first", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Ask(context.Background(), &session, &def.Emp3r0rAgent{Tag: "b"}, "second", nil); err != nil {
		t.Fatal(err)
	}
	for _, msg := range provider.requests[1] {
		if msg.Content == "first" {
			t.Fatal("history from the previous target leaked into the new target")
		}
	}
}

func TestTrimHistoryKeepsCompleteTurns(t *testing.T) {
	msgs := []Message{
		{Role: "user", Content: "u1"},
		{Role: "assistant", Content: "a1"},
		{Role: "user", Content: "u2"},
		{Role: "assistant", ToolCalls: []ToolCall{{ID: "c"}}},
		{Role: "tool", ToolCallID: "c", Content: "r"},
		{Role: "user", Content: "u3"},
	}
	got := trimHistory(msgs, 3)
	if len(got) == 0 || got[0].Role != "user" || got[0].Content != "u3" {
		t.Fatalf("trimHistory = %+v", got)
	}
}

func TestHarnessPassesDeltasToCaller(t *testing.T) {
	provider := &fakeProvider{replies: []Message{{Role: "assistant", Content: "hello"}}}
	cfg := DefaultConfig()
	h, err := NewWithProvider(cfg, provider)
	if err != nil {
		t.Fatal(err)
	}
	var got strings.Builder
	var session Session
	text, err := h.Ask(context.Background(), &session, nil, "hi", func(delta string) {
		got.WriteString(delta)
	})
	if err != nil {
		t.Fatal(err)
	}
	if text != "hello" || got.String() != "hello" {
		t.Fatalf("text=%q deltas=%q", text, got.String())
	}
}

func TestHarnessReviewCommandDoesNotExecute(t *testing.T) {
	provider := &fakeProvider{replies: []Message{
		{
			Role: "assistant",
			ToolCalls: []ToolCall{{
				ID:       "call-1",
				Type:     "function",
				Function: ToolCallFunction{Name: "review_command", Arguments: `{"command":"whoami"}`},
			}},
		},
		{Role: "assistant", Content: "reviewed"},
	}}
	h, err := NewWithProvider(DefaultConfig(), provider)
	if err != nil {
		t.Fatal(err)
	}
	var session Session
	text, err := h.Ask(context.Background(), &session, &def.Emp3r0rAgent{Tag: "agent-1"}, "review", nil)
	if err != nil {
		t.Fatal(err)
	}
	if text != "reviewed" {
		t.Fatalf("answer = %q", text)
	}
	var result string
	for _, msg := range provider.requests[1] {
		if msg.Role == "tool" && msg.ToolCallID == "call-1" {
			result = msg.Content
		}
	}
	if !strings.Contains(result, `"kind":"exec"`) || !strings.Contains(result, `"opsec"`) {
		t.Fatalf("tool result = %q", result)
	}
	if strings.Contains(result, "job_id") || strings.Contains(result, "executed") {
		t.Fatalf("review executed something: %q", result)
	}
}

func TestModuleCatalogIncludesInstalledModules(t *testing.T) {
	def.Modules.Store("zz_catalog_linux", &def.ModuleConfig{
		Name: "zz_catalog_linux", Comment: "linux helper", Platform: "Linux",
	})
	def.Modules.Store("zz_catalog_windows", &def.ModuleConfig{
		Name: "zz_catalog_windows", Comment: "windows helper", Platform: "Windows",
	})
	t.Cleanup(func() {
		def.Modules.Delete("zz_catalog_linux")
		def.Modules.Delete("zz_catalog_windows")
	})

	catalog := moduleCatalog(&def.Emp3r0rAgent{GOOS: "linux"})
	if !strings.Contains(catalog, "zz_catalog_linux") {
		t.Fatalf("catalog missing linux module:\n%s", catalog)
	}
	if strings.Contains(catalog, "zz_catalog_windows") {
		t.Fatalf("catalog leaked a windows module:\n%s", catalog)
	}
}

func TestFallbackAnswerUsesLatestToolResults(t *testing.T) {
	convo := []Message{
		{Role: "user", Content: "q"},
		{Role: "tool", ToolCallID: "1", Content: "first result"},
		{Role: "tool", ToolCallID: "2", Content: "second result"},
	}
	answer := fallbackAnswer(convo)
	if !strings.Contains(answer, "second result") {
		t.Fatalf("answer = %q", answer)
	}
}

func TestHarnessReusesDuplicateToolResult(t *testing.T) {
	provider := &fakeProvider{replies: []Message{
		{Role: "assistant", ToolCalls: []ToolCall{
			{ID: "call-1", Type: "function", Function: ToolCallFunction{Name: "list_agents", Arguments: "{}"}},
			{ID: "call-2", Type: "function", Function: ToolCallFunction{Name: "list_agents", Arguments: "{}"}},
		}},
		{Role: "assistant", Content: "done"},
	}}
	h, err := NewWithProvider(DefaultConfig(), provider)
	if err != nil {
		t.Fatal(err)
	}
	var session Session
	if _, err := h.Ask(context.Background(), &session, nil, "loop", nil); err != nil {
		t.Fatal(err)
	}
	var toolMsgs []Message
	for _, msg := range provider.requests[1] {
		if msg.Role == "tool" {
			toolMsgs = append(toolMsgs, msg)
		}
	}
	if len(toolMsgs) != 2 {
		t.Fatalf("tool messages = %d", len(toolMsgs))
	}
	if !strings.Contains(toolMsgs[1].Content, "duplicate call") {
		t.Fatalf("second result not marked duplicate: %q", toolMsgs[1].Content)
	}
}
