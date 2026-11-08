package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/assistant"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/opsec"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// chanWriter delivers one encoded JSON-RPC message per channel value.
type chanWriter struct {
	ch chan []byte
}

func (w *chanWriter) Write(p []byte) (int, error) {
	w.ch <- append([]byte(nil), p...)
	return len(p), nil
}

type harness struct {
	t      *testing.T
	in     *io.PipeWriter
	out    chan []byte
	cancel context.CancelFunc
	done   chan error
}

func startServer(t *testing.T, opts Options) *harness {
	t.Helper()
	inR, inW := io.Pipe()
	out := &chanWriter{ch: make(chan []byte, 32)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, inR, out, opts) }()
	t.Cleanup(func() {
		cancel()
		_ = inW.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Serve did not return")
		}
	})
	return &harness{t: t, in: inW, out: out.ch, cancel: cancel, done: done}
}

func (h *harness) send(v any) {
	h.t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.in.Write(append(b, '\n')); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) next() response {
	h.t.Helper()
	select {
	case b := <-h.out:
		var resp response
		if err := json.Unmarshal(bytes.TrimSpace(b), &resp); err != nil {
			h.t.Fatalf("decode %q: %v", b, err)
		}
		return resp
	case <-time.After(2 * time.Second):
		h.t.Fatal("no response")
		return response{}
	}
}

type fakeTools struct {
	tools map[string]assistant.Tool
}

func newFakeTools() *fakeTools {
	return &fakeTools{tools: map[string]assistant.Tool{
		"echo": {
			Def: assistant.ToolDef{
				Type: "function",
				Function: assistant.FunctionDef{
					Name:        "echo",
					Description: "echo the arguments",
					Parameters:  map[string]any{"type": "object", "properties": map[string]any{}},
				},
			},
			ReadOnly: true,
			Run: func(_ context.Context, args json.RawMessage) (any, error) {
				return map[string]any{"args": json.RawMessage(args)}, nil
			},
		},
		"fail": {
			Def: assistant.ToolDef{
				Type: "function",
				Function: assistant.FunctionDef{
					Name:       "fail",
					Parameters: map[string]any{"type": "object"},
				},
			},
			Run: func(context.Context, json.RawMessage) (any, error) {
				return nil, fmt.Errorf("deliberate failure")
			},
		},
		"wait": {
			Def: assistant.ToolDef{
				Type: "function",
				Function: assistant.FunctionDef{
					Name:       "wait",
					Parameters: map[string]any{"type": "object"},
				},
			},
			Run: func(ctx context.Context, _ json.RawMessage) (any, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
		},
	}}
}

func (f *fakeTools) Definitions() []assistant.ToolDef {
	names := make([]string, 0, len(f.tools))
	for name := range f.tools {
		names = append(names, name)
	}
	sort.Strings(names)
	defs := make([]assistant.ToolDef, 0, len(names))
	for _, name := range names {
		defs = append(defs, f.tools[name].Def)
	}
	return defs
}

func (f *fakeTools) Lookup(name string) (assistant.Tool, bool) {
	tool, ok := f.tools[name]
	return tool, ok
}

func (f *fakeTools) Call(ctx context.Context, name string, args json.RawMessage) (any, error) {
	tool, ok := f.tools[name]
	if !ok {
		return nil, fmt.Errorf("unknown tool %q", name)
	}
	return tool.Run(ctx, args)
}

func fakeOptions() Options {
	tools := newFakeTools()
	return Options{
		Name:    "test-server",
		Version: "1.0",
		Tools:   func() ToolSet { return tools },
	}
}

func mustInitialize(t *testing.T, h *harness) response {
	t.Helper()
	h.send(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "test", "version": "1"},
		},
	})
	resp := h.next()
	if resp.Error != nil {
		t.Fatalf("initialize error: %+v", resp.Error)
	}
	h.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	return resp
}

func TestInitializeNegotiatesVersion(t *testing.T) {
	h := startServer(t, fakeOptions())
	resp := mustInitialize(t, h)
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("result = %T", resp.Result)
	}
	// A known older revision is echoed so older clients keep working.
	if result["protocolVersion"] != "2024-11-05" {
		t.Fatalf("protocolVersion = %v", result["protocolVersion"])
	}
	info, _ := result["serverInfo"].(map[string]any)
	if info["name"] != "test-server" || info["version"] != "1.0" {
		t.Fatalf("serverInfo = %v", info)
	}
	caps, _ := result["capabilities"].(map[string]any)
	if _, ok := caps["tools"]; !ok {
		t.Fatalf("capabilities = %v", caps)
	}
}

func TestInitializeUnknownVersionUsesLatest(t *testing.T) {
	h := startServer(t, fakeOptions())
	h.send(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"protocolVersion": "1999-01-01"},
	})
	result, _ := h.next().Result.(map[string]any)
	if result["protocolVersion"] != ProtocolVersion {
		t.Fatalf("protocolVersion = %v", result["protocolVersion"])
	}
}

func TestToolsListBeforeInitializeIsRejected(t *testing.T) {
	h := startServer(t, fakeOptions())
	h.send(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
	resp := h.next()
	if resp.Error == nil || resp.Error.Code != -32002 {
		t.Fatalf("error = %+v", resp.Error)
	}
}

func TestToolsListAndReadOnlyAnnotations(t *testing.T) {
	h := startServer(t, fakeOptions())
	mustInitialize(t, h)
	h.send(map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
	resp := h.next()
	result, _ := resp.Result.(map[string]any)
	tools, _ := result["tools"].([]any)
	if len(tools) != 3 {
		t.Fatalf("tools = %d, want 3", len(tools))
	}
	names := make([]string, 0, len(tools))
	for _, raw := range tools {
		tool := raw.(map[string]any)
		names = append(names, tool["name"].(string))
	}
	want := []string{"echo", "fail", "wait"}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("names = %v, want %v", names, want)
		}
	}
	first := tools[0].(map[string]any)
	ann, _ := first["annotations"].(map[string]any)
	if ann["readOnlyHint"] != true {
		t.Fatalf("annotations = %v", ann)
	}
	if _, ok := first["inputSchema"].(map[string]any); !ok {
		t.Fatalf("missing inputSchema: %v", first)
	}
}

func TestToolsCallReturnsJSONResult(t *testing.T) {
	h := startServer(t, fakeOptions())
	mustInitialize(t, h)
	h.send(map[string]any{
		"jsonrpc": "2.0", "id": 4, "method": "tools/call",
		"params": map[string]any{"name": "echo", "arguments": map[string]any{"x": 1}},
	})
	result, _ := h.next().Result.(map[string]any)
	if result["isError"] == true {
		t.Fatalf("result = %v", result)
	}
	content, _ := result["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("content = %v", content)
	}
	text := content[0].(map[string]any)["text"].(string)
	var payload map[string]any
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("text %q: %v", text, err)
	}
	if payload["args"].(map[string]any)["x"] != float64(1) {
		t.Fatalf("payload = %v", payload)
	}
}

func TestToolsCallReportsToolError(t *testing.T) {
	h := startServer(t, fakeOptions())
	mustInitialize(t, h)
	h.send(map[string]any{
		"jsonrpc": "2.0", "id": 5, "method": "tools/call",
		"params": map[string]any{"name": "fail", "arguments": map[string]any{}},
	})
	result, _ := h.next().Result.(map[string]any)
	if result["isError"] != true {
		t.Fatalf("result = %v", result)
	}
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	if text != "fail: deliberate failure" {
		t.Fatalf("text = %q", text)
	}
}

func TestCancellationStopsInflightTool(t *testing.T) {
	h := startServer(t, fakeOptions())
	mustInitialize(t, h)
	h.send(map[string]any{
		"jsonrpc": "2.0", "id": 6, "method": "tools/call",
		"params": map[string]any{"name": "wait", "arguments": map[string]any{}},
	})
	h.send(map[string]any{
		"jsonrpc": "2.0", "method": "notifications/cancelled",
		"params": map[string]any{"requestId": 6, "reason": "test"},
	})
	result, _ := h.next().Result.(map[string]any)
	if result["isError"] != true {
		t.Fatalf("result = %v", result)
	}
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	if text != "wait: context canceled" {
		t.Fatalf("text = %q", text)
	}
}

type recordingExecutor struct {
	execs     []string
	uploads   []string
	downloads []string
}

func (r *recordingExecutor) RunModule(context.Context, *def.Emp3r0rAgent, string, map[string]string) (string, error) {
	return "job-module", nil
}

func (r *recordingExecutor) BuildLocalModule(context.Context, string, map[string]string) (string, error) {
	return "build log", nil
}

func (r *recordingExecutor) RunExec(_ context.Context, _ *def.Emp3r0rAgent, command string, _ bool) (string, error) {
	r.execs = append(r.execs, command)
	return "job-exec", nil
}

func (r *recordingExecutor) RunCommand(context.Context, *def.Emp3r0rAgent, string) (string, error) {
	return "job-command", nil
}

func (r *recordingExecutor) UploadFile(_ context.Context, _ *def.Emp3r0rAgent, src, dst string) (string, error) {
	r.uploads = append(r.uploads, src+" -> "+dst)
	return "job-upload", nil
}

func (r *recordingExecutor) DownloadFile(_ context.Context, _ *def.Emp3r0rAgent, path, filter string, recursive bool) (string, error) {
	r.downloads = append(r.downloads, path)
	return "/downloads/" + filepath.Base(path), nil
}
func (r *recordingExecutor) ReloadModules(context.Context) error { return nil }

func TestMergedToolsetScreensActions(t *testing.T) {
	target := &def.Emp3r0rAgent{Tag: "target-1", GOOS: "linux", AgentImpl: "go"}
	exec := &recordingExecutor{}
	policy := opsec.DefaultPolicy()
	policy.Capabilities["process-creation"] = opsec.ModeAllow
	policy.Capabilities["destructive"] = opsec.ModeBlock
	actions := &Actions{
		Target:   func() *def.Emp3r0rAgent { return target },
		Policy:   policy,
		Executor: exec,
	}
	opts := Options{
		Name: "real",
		Tools: func() ToolSet {
			return NewToolset(assistant.NewToolset(assistant.DefaultConfig(), target), actions)
		},
	}
	h := startServer(t, opts)
	mustInitialize(t, h)

	h.send(map[string]any{"jsonrpc": "2.0", "id": 7, "method": "tools/list"})
	result, _ := h.next().Result.(map[string]any)
	tools, _ := result["tools"].([]any)
	if len(tools) != 19 {
		t.Fatalf("tools = %d, want 19", len(tools))
	}
	seen := map[string]bool{}
	for _, raw := range tools {
		seen[raw.(map[string]any)["name"].(string)] = true
	}
	for _, name := range []string{"run_module", "run_exec", "command", "upload_file", "download_file", "reload_modules", "select_agent", "generate", "generate_c"} {
		if !seen[name] {
			t.Fatalf("missing action tool %q", name)
		}
	}

	h.send(map[string]any{
		"jsonrpc": "2.0", "id": 8, "method": "tools/call",
		"params": map[string]any{"name": "run_exec", "arguments": map[string]any{"command": "whoami"}},
	})
	call, _ := h.next().Result.(map[string]any)
	if call["isError"] == true {
		t.Fatalf("call = %v", call)
	}
	text := call["content"].([]any)[0].(map[string]any)["text"].(string)
	var payload map[string]any
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("text %q: %v", text, err)
	}
	if payload["executed"] != true || payload["job_id"] != "job-exec" {
		t.Fatalf("payload = %v", payload)
	}
	if len(exec.execs) != 1 || exec.execs[0] != "whoami" {
		t.Fatalf("executor = %v", exec.execs)
	}

	h.send(map[string]any{
		"jsonrpc": "2.0", "id": 9, "method": "tools/call",
		"params": map[string]any{"name": "run_exec", "arguments": map[string]any{"command": "rm -rf /"}},
	})
	call, _ = h.next().Result.(map[string]any)
	text = call["content"].([]any)[0].(map[string]any)["text"].(string)
	payload = nil
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("text %q: %v", text, err)
	}
	if payload["blocked"] != true || payload["executed"] != false {
		t.Fatalf("payload = %v", payload)
	}
	if len(exec.execs) != 1 {
		t.Fatalf("blocked action reached the executor: %v", exec.execs)
	}
}

func TestProtocolErrors(t *testing.T) {
	h := startServer(t, fakeOptions())
	mustInitialize(t, h)

	// Malformed JSON gets a parse error with a null id.
	if _, err := h.in.Write([]byte("not json\n")); err != nil {
		t.Fatal(err)
	}
	resp := h.next()
	if resp.Error == nil || resp.Error.Code != -32700 {
		t.Fatalf("parse error = %+v", resp.Error)
	}
	if string(resp.ID) != "null" {
		t.Fatalf("parse error id = %s", resp.ID)
	}

	h.send(map[string]any{"jsonrpc": "2.0", "id": 9, "method": "does/not/exist"})
	resp = h.next()
	if resp.Error == nil || resp.Error.Code != -32601 {
		t.Fatalf("method error = %+v", resp.Error)
	}

	h.send(map[string]any{"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": map[string]any{}})
	resp = h.next()
	if resp.Error == nil || resp.Error.Code != -32602 {
		t.Fatalf("params error = %+v", resp.Error)
	}

	h.send(map[string]any{
		"jsonrpc": "2.0", "id": 13, "method": "tools/call",
		"params": map[string]any{"name": "not-a-tool", "arguments": map[string]any{}},
	})
	resp = h.next()
	if resp.Error == nil || resp.Error.Code != -32602 {
		t.Fatalf("unknown tool error = %+v", resp.Error)
	}
}

func TestNotificationProducesNoResponse(t *testing.T) {
	h := startServer(t, fakeOptions())
	mustInitialize(t, h)
	h.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	h.send(map[string]any{"jsonrpc": "2.0", "id": 11, "method": "ping"})
	resp := h.next()
	if string(resp.ID) != "11" {
		t.Fatalf("first response id = %s, expected ping", resp.ID)
	}
}

func TestOversizedMessageIsRejectedAndStreamContinues(t *testing.T) {
	h := startServer(t, fakeOptions())
	mustInitialize(t, h)

	// One line larger than the bound, delivered through a reader that reports
	// ErrBufferFull in slices.
	huge := append(bytes.Repeat([]byte("x"), maxRequestBytes+1024), '\n')
	if _, err := h.in.Write(huge); err != nil {
		t.Fatal(err)
	}
	resp := h.next()
	if resp.Error == nil || resp.Error.Code != -32700 {
		t.Fatalf("oversize error = %+v", resp.Error)
	}

	h.send(map[string]any{"jsonrpc": "2.0", "id": 12, "method": "ping"})
	if string(h.next().ID) != "12" {
		t.Fatal("stream did not continue after an oversized message")
	}
}

// The production toolset must satisfy the MCP interface and answer a read-only
// call without a C2: the bridge is the only part the fake tools cannot cover.
func TestRealToolsetServesReadOnlyTools(t *testing.T) {
	opts := Options{
		Name: "real",
		Tools: func() ToolSet {
			return assistant.NewToolset(assistant.DefaultConfig(), nil)
		},
	}
	h := startServer(t, opts)
	mustInitialize(t, h)

	h.send(map[string]any{"jsonrpc": "2.0", "id": 20, "method": "tools/list"})
	result, _ := h.next().Result.(map[string]any)
	tools, _ := result["tools"].([]any)
	if len(tools) != 8 {
		t.Fatalf("read-only tools = %d, want 8", len(tools))
	}

	h.send(map[string]any{
		"jsonrpc": "2.0", "id": 21, "method": "tools/call",
		"params": map[string]any{"name": "list_agents", "arguments": map[string]any{}},
	})
	call, _ := h.next().Result.(map[string]any)
	if call["isError"] == true {
		t.Fatalf("list_agents failed: %v", call)
	}
	text := call["content"].([]any)[0].(map[string]any)["text"].(string)
	var payload map[string]any
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("text %q: %v", text, err)
	}
	if _, ok := payload["agents"]; !ok {
		t.Fatalf("payload = %v", payload)
	}
}

// bufio.Reader is exercised directly so the framing edge cases do not depend on
// pipe buffering.
func TestReadMessageFraming(t *testing.T) {
	r := bufio.NewReaderSize(bytes.NewReader([]byte("{\"a\":1}\n{\"b\":2}\n")), 4)
	first, err := readMessage(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != `{"a":1}` {
		t.Fatalf("first = %q", first)
	}
	second, err := readMessage(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != `{"b":2}` {
		t.Fatalf("second = %q", second)
	}
	if _, err := readMessage(r); err != io.EOF {
		t.Fatalf("err = %v, want EOF", err)
	}
}

func TestProtocolRunsOperatorCommand(t *testing.T) {
	target := &def.Emp3r0rAgent{Tag: "target-1", GOOS: "linux", AgentImpl: "go"}
	var ran string
	actions := &Actions{
		Target:      func() *def.Emp3r0rAgent { return target },
		Policy:      opsec.DefaultPolicy(),
		RunOperator: func(_ context.Context, line string) error { ran = line; return nil },
	}
	opts := Options{
		Name: "real",
		Tools: func() ToolSet {
			return NewToolset(assistant.NewToolset(assistant.DefaultConfig(), target), actions)
		},
	}
	h := startServer(t, opts)
	mustInitialize(t, h)

	h.send(map[string]any{
		"jsonrpc": "2.0", "id": 10, "method": "tools/call",
		"params": map[string]any{"name": "command", "arguments": map[string]any{"command": "/target 1a2b3c4d"}},
	})
	call, _ := h.next().Result.(map[string]any)
	if call["isError"] == true {
		t.Fatalf("call = %v", call)
	}
	text := call["content"].([]any)[0].(map[string]any)["text"].(string)
	var payload map[string]any
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("text %q: %v", text, err)
	}
	if payload["executed"] != true {
		t.Fatalf("payload = %v", payload)
	}
	if ran != "target 1a2b3c4d" {
		t.Fatalf("runner received %q", ran)
	}
}
