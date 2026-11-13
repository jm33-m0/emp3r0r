package detection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
)

func TestEvolveAgentEditsBuildsAndComparesPayloads(t *testing.T) {
	moduleDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(moduleDir, "bootstrap.c"),
		[]byte("const char *process = \"OLD\";\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var buildCount atomic.Int32
	build := func(_ string, _ map[string]string) (string, error) {
		n := buildCount.Add(1)
		path := filepath.Join(t.TempDir(), fmt.Sprintf("loader%d.exe", n))
		if err := os.WriteFile(path, append([]byte("MZpayload"), byte(n)), 0o600); err != nil {
			return "", err
		}
		return fmt.Sprintf("[+] generated payload: %s (10 bytes)\n", path), nil
	}
	server, dynamicCalls := fakeEvolveSandbox(t)
	provider := &scriptedToolProvider{turns: []llm.Message{
		toolUseMessage("edit-1", "EditSource", map[string]any{
			"file": "bootstrap.c", "old_string": "OLD", "new_string": "NEW",
			"reason": "remove the detected default",
		}),
		toolUseMessage("cycle-2", "DetectionCycle", map[string]any{"note": "after edit"}),
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
			llm.TextBlock(`{"summary":"edited","verdicts_before":["Behavior:Win32/Test.A"],"verdicts_after":[],"edits":[{"file":"bootstrap.c","reason":"default"}],"residual":[],"cycles":2}`),
		}},
	}}
	storeRoot := t.TempDir()
	shellcode := filepath.Join(t.TempDir(), "agent.bin")
	if err := os.WriteFile(shellcode, []byte("shellcode"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := RunEvolve(ctx, EvolveConfig{
		Provider: provider, Model: "scripted",
		Module: "loader_windows", ModuleDir: moduleDir,
		Shellcode: shellcode, SandboxURL: server.URL,
		StoreRoot: storeRoot, Stages: []string{"dynamic"},
		Iterations: 2, Turns: 8, Build: build,
		Logf: func(string) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Cycles) != 2 {
		t.Fatalf("cycles = %d", len(result.Cycles))
	}
	if dynamicCalls.Load() != 2 {
		t.Fatalf("dynamic calls = %d", dynamicCalls.Load())
	}
	data, err := os.ReadFile(filepath.Join(moduleDir, "bootstrap.c"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "NEW") {
		t.Fatalf("edit not applied: %q", data)
	}
	verify, err := OpenTelemetryDB(filepath.Join(storeRoot, "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer verify.Close()
	payloads, err := verify.ListPayloads(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 2 || payloads[0].ParentID != result.Cycles[0].PayloadID {
		t.Fatalf("payloads = %+v", payloads)
	}
	edits, err := verify.EditsForPayload(context.Background(), result.Cycles[1].PayloadKey)
	if err != nil || len(edits) != 1 || edits[0].File != "bootstrap.c" {
		t.Fatalf("edits = %+v err=%v", edits, err)
	}
	_ = data
}

type scriptedToolProvider struct {
	turns []llm.Message
	index atomic.Int32
}

func toolUseMessage(id, name string, input map[string]any) llm.Message {
	raw, _ := json.Marshal(input)
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{
		Type: llm.BlockToolUse, ID: id, Name: name, Input: raw,
	}}}
}

func (p *scriptedToolProvider) Stream(_ context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		n := int(p.index.Add(1)) - 1
		if n >= len(p.turns) {
			n = len(p.turns) - 1
		}
		message := p.turns[n]
		if !yield(llm.StreamEvent{Type: llm.SEMessageStart}, nil) {
			return
		}
		stop := "end_turn"
		for _, block := range message.Content {
			if block.Type == llm.BlockToolUse {
				stop = "tool_use"
				if !yield(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: block.ID, ToolName: block.Name}, nil) {
					return
				}
				if !yield(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: string(block.Input)}, nil) {
					return
				}
				continue
			}
			if block.Type == llm.BlockText {
				if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: block.Text}, nil) {
					return
				}
			}
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: stop}, nil) {
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func (p *scriptedToolProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{}, "", llm.Usage{}, nil
}

func fakeEvolveSandbox(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/health":
			fmt.Fprint(w, `{"scanners":{"rows":[{"group":"dynamic","name":"rededr","status":"ok","enabled":true,"exists":true}]},"edr_agents":{"agents":[]},"issues":[]}`)
		case r.URL.Path == "/api/edr/profiles":
			fmt.Fprint(w, `{"profiles":[]}`)
		case r.URL.Path == "/upload":
			fmt.Fprint(w, `{"file_info":{"md5":"0123456789abcdef0123456789abcdef","sha256":"abc","size":10,"original_name":"loader.exe"}}`)
		case strings.HasPrefix(r.URL.Path, "/analyze/dynamic/"):
			fmt.Fprint(w, `{"status":"success"}`)
		case strings.HasPrefix(r.URL.Path, "/api/results/dynamic/"):
			n := calls.Add(1)
			extra := ""
			if n > 1 {
				extra = `,{"type":"etw","event":"CreateNewFileInfo ","etw_provider_name":"Microsoft-Windows-Kernel-File","etw_pid":100,"filename":"\\Device\\HarddiskVolume3\\Users\\x\\Temp\\new.bin","trace_id":2}`
			}
			fmt.Fprintf(w, `{"rededr":{"findings":{"events":[
				{"type":"process_query","func":"peb","pid":100,"image_path":"C:\\Users\\x\\loader.exe"},
				{"type":"etw","event":"ProcessStartStart ","etw_provider_name":"Microsoft-Windows-Kernel-Process","etw_pid":100,"processid":200,"imagename":"\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe","trace_id":1},
				{"type":"etw","event":"Behavior Monitoring BmDetection","etw_provider_name":"Microsoft-Antimalware-Engine","etw_pid":300,"pid":100,"name":"Behavior:Win32/Test.A","trace_id":1}%s]}}}`, extra)
		case strings.HasPrefix(r.URL.Path, "/api/results/risk/"):
			fmt.Fprint(w, `{"risk_score":10,"risk_level":"Low","risk_factors":[]}`)
		case strings.HasPrefix(r.URL.Path, "/api/results/info/"):
			fmt.Fprint(w, `{}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, calls
}

func TestLoggingProviderStreamsModelOutput(t *testing.T) {
	var lines []string
	provider := &loggingProvider{
		next: scriptedProvider{answer: "hello model"},
		logf: func(line string) { lines = append(lines, line) },
	}
	for event, err := range provider.Stream(context.Background(), llm.CompletionRequest{}) {
		if err != nil {
			t.Fatal(err)
		}
		_ = event
	}
	if len(lines) != 1 || lines[0] != "[model] hello model" {
		t.Fatalf("lines = %+v", lines)
	}
}

func TestEvolveDoesNotBuildWhenSandboxIsDown(t *testing.T) {
	dir := t.TempDir()
	shellcode := filepath.Join(dir, "agent.bin")
	if err := os.WriteFile(shellcode, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	builds := 0
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	_, err := RunEvolve(ctx, EvolveConfig{
		Provider: scriptedProvider{answer: "{}"}, Model: "scripted",
		Module: "loader_windows", ModuleDir: dir, Shellcode: shellcode,
		SandboxURL: "http://127.0.0.1:1", StoreRoot: t.TempDir(),
		Stages: []string{"dynamic"}, Iterations: 1, Turns: 1, RetryBase: time.Millisecond,
		Build: func(string, map[string]string) (string, error) {
			builds++
			return "", nil
		},
		Logf: func(string) {},
	})
	if err == nil {
		t.Fatal("expected the context deadline")
	}
	if builds != 0 {
		t.Fatalf("build ran before the sandbox check: %d", builds)
	}
}

func TestEvolveFallsBackWhenAgentTextIsNotJSON(t *testing.T) {
	moduleDir := t.TempDir()
	shellcode := filepath.Join(t.TempDir(), "agent.bin")
	if err := os.WriteFile(shellcode, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	build := func(_ string, _ map[string]string) (string, error) {
		path := filepath.Join(t.TempDir(), "loader.exe")
		if err := os.WriteFile(path, []byte("MZpayload"), 0o600); err != nil {
			return "", err
		}
		return fmt.Sprintf("[+] generated payload: %s (9 bytes)\n", path), nil
	}
	server, _ := fakeEvolveSandbox(t)
	result, err := RunEvolve(context.Background(), EvolveConfig{
		Provider: scriptedProvider{answer: "I reviewed the payload but did not return JSON."},
		Model:    "scripted", Module: "loader_windows", ModuleDir: moduleDir,
		Shellcode: shellcode, SandboxURL: server.URL, StoreRoot: t.TempDir(),
		Stages: []string{"dynamic"}, Iterations: 1, Turns: 2, Build: build,
		Logf: func(string) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(result.Answer), "did not return the required JSON object") {
		t.Fatalf("answer = %s", result.Answer)
	}
	if len(result.Cycles) != 1 {
		t.Fatalf("cycles = %d", len(result.Cycles))
	}
}

type failOnceProvider struct {
	inner  llm.Provider
	failed atomic.Bool
}

func (p *failOnceProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	if !p.failed.Swap(true) {
		return func(yield func(llm.StreamEvent, error) bool) {
			yield(llm.StreamEvent{}, errors.New("transient provider failure"))
		}
	}
	return p.inner.Stream(ctx, req)
}

func (p *failOnceProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return p.inner.Complete(ctx, req)
}

func TestEvolveRecoversFromAgentSessionFailure(t *testing.T) {
	moduleDir := t.TempDir()
	shellcode := filepath.Join(t.TempDir(), "agent.bin")
	if err := os.WriteFile(shellcode, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	build := func(_ string, _ map[string]string) (string, error) {
		path := filepath.Join(t.TempDir(), "loader.exe")
		if err := os.WriteFile(path, []byte("MZpayload"), 0o600); err != nil {
			return "", err
		}
		return fmt.Sprintf("[+] generated payload: %s (9 bytes)\n", path), nil
	}
	server, _ := fakeEvolveSandbox(t)
	provider := &failOnceProvider{inner: scriptedProvider{answer: `{"summary":"recovered","edits":[],"residual":[]}`}}
	result, err := RunEvolve(context.Background(), EvolveConfig{
		Provider: provider, Model: "scripted",
		Module: "loader_windows", ModuleDir: moduleDir, Shellcode: shellcode,
		SandboxURL: server.URL, StoreRoot: t.TempDir(), RetryBase: time.Millisecond,
		Stages: []string{"dynamic"}, Iterations: 1, Turns: 2, Build: build,
		Logf: func(string) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !strings.Contains(string(result.Answer), "recovered") {
		t.Fatalf("result = %+v", result)
	}
}

func TestRenderLoopReport(t *testing.T) {
	answer := map[string]any{
		"loop_id":         "loop-test",
		"summary":         "removed the verdict",
		"verdicts_before": []any{"Behavior:Win32/Test.A"},
		"verdicts_after":  []any{},
		"residual":        []any{".rdata entropy is inherent"},
	}
	cycles := []Cycle{{
		LoopID: "loop-test", Iteration: 1, PayloadID: 1,
		PayloadKey: "sha256:abcdef0123456789", Score: 10, Level: "Low",
		Findings: 3, Verdicts: 1, TraceID: 4,
		Summary: `{"payload_table":"payload_abcdef0123456789"}`,
	}}
	report := RenderLoopReport(answer, cycles, []EditRecord{{
		File: "build.sh", Reason: "switch the default process",
	}})
	for _, want := range []string{
		"# Detection loop `loop-test`", "## Outcome", "removed the verdict",
		"## Achieved objectives", "build.sh", "switch the default process",
		"## Cycles", "payload_abcdef0123456789", "## Residual findings",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
}
