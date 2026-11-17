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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
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
		if err := os.WriteFile(path, append([]byte("MZ"+strings.Repeat("M", 40000)), byte(n)), 0o600); err != nil {
			return "", err
		}
		return fmt.Sprintf("[+] generated payload: %s (10 bytes)\n", path), nil
	}
	server, dynamicCalls := fakeEvolveSandbox(t)
	provider := &roleScriptProvider{scripts: map[string][]llm.Message{
		"planner": {
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
				llm.TextBlock(`{"action":"test","mechanism":"self-load","prediction":"the defender behavior disappears","editor_brief":"remove the detected default from bootstrap.c","reason":"the baseline has a real verdict"}`),
			}},
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
				llm.TextBlock(`{"action":"stop","reason":"done","final":{"summary":"edited","verdicts_before":["Behavior:Win32/Test.A"],"verdicts_after":[],"edits":[{"file":"bootstrap.c","reason":"default"}],"residual":[],"cycles":2}}`),
			}},
		},
		"editor": {
			toolUseMessage("edit-1", "EditSource", map[string]any{
				"file": "bootstrap.c", "old_string": "OLD", "new_string": "NEW",
				"reason": "remove the detected default",
			}),
			toolUseMessage("cycle-2", "DetectionCycle", map[string]any{"note": "after edit"}),
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
				llm.TextBlock(`{"summary":"edited","edits":[{"file":"bootstrap.c","reason":"default"}]}`),
			}},
		},
	}}
	storeRoot := t.TempDir()
	shellcode := filepath.Join(t.TempDir(), "agent.bin")
	if err := os.WriteFile(shellcode, []byte(strings.Repeat("S", 40000)), 0o600); err != nil {
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
		Logf: nil,
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

func toolUseMessage(id, name string, input map[string]any) llm.Message {
	raw, _ := json.Marshal(input)
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{
		Type: llm.BlockToolUse, ID: id, Name: name, Input: raw,
	}}}
}

// roleScriptProvider selects a script by worker system prompt, so a test can
// drive the planner, editor, and debugger independently.
type roleScriptProvider struct {
	mu      sync.Mutex
	scripts map[string][]llm.Message
	index   map[string]int
}

func workerRole(req llm.CompletionRequest) string {
	system := strings.Join(req.System, "\n")
	switch {
	case strings.Contains(system, "planner and coordinator"):
		return "planner"
	case strings.Contains(system, "editor (evasion) worker"):
		return "editor"
	case strings.Contains(system, "debugger worker"):
		return "debugger"
	default:
		return "editor"
	}
}

func (p *roleScriptProvider) next(req llm.CompletionRequest) llm.Message {
	role := workerRole(req)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.index == nil {
		p.index = make(map[string]int)
	}
	turns := p.scripts[role]
	if len(turns) == 0 {
		return llm.Message{}
	}
	n := p.index[role]
	p.index[role]++
	if n >= len(turns) {
		n = len(turns) - 1
	}
	return turns[n]
}

func (p *roleScriptProvider) Stream(_ context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		emitScriptedMessage(yield, p.next(req))
	}
}

func (p *roleScriptProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{}, "", llm.Usage{}, nil
}

// emitScriptedMessage turns one assistant message into the event stream the
// harness expects.
func emitScriptedMessage(yield func(llm.StreamEvent, error) bool, message llm.Message) {
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
	type entry struct {
		class logging.Class
		text  string
	}
	var lines []entry
	provider := &loggingProvider{
		next: scriptedProvider{answer: "hello model"},
		logf: func(class logging.Class, format string, a ...any) {
			lines = append(lines, entry{class: class, text: fmt.Sprintf(format, a...)})
		},
	}
	for event, err := range provider.Stream(context.Background(), llm.CompletionRequest{}) {
		if err != nil {
			t.Fatal(err)
		}
		_ = event
	}
	if len(lines) != 1 || lines[0].class != logging.ClassModel || lines[0].text != "hello model" {
		t.Fatalf("lines = %+v", lines)
	}
}

func TestEvolveDoesNotBuildWhenSandboxIsDown(t *testing.T) {
	dir := t.TempDir()
	shellcode := filepath.Join(dir, "agent.bin")
	if err := os.WriteFile(shellcode, []byte(strings.Repeat("X", 40000)), 0o600); err != nil {
		t.Fatal(err)
	}
	builds := 0
	provider := &captureProvider{answer: `{"summary":"sandbox is down","edits":[],"residual":[]}`}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	_, err := RunEvolve(ctx, EvolveConfig{
		Provider: provider, Model: "scripted",
		Module: "loader_windows", ModuleDir: dir, Shellcode: shellcode,
		SandboxURL: "http://127.0.0.1:1", StoreRoot: t.TempDir(),
		Stages: []string{"dynamic"}, Iterations: 1, Turns: 1, RetryBase: 50 * time.Millisecond,
		Build: func(string, map[string]string) (string, error) {
			builds++
			return "", nil
		},
		Logf: nil,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the caller deadline; the loop must keep retrying", err)
	}
	if builds != 0 {
		t.Fatalf("build ran before the sandbox check: %d", builds)
	}
	if len(provider.requests) < 2 || !strings.Contains(provider.requests[0], "unreachable") {
		t.Fatalf("model did not receive the sandbox failure on retries: %v", provider.requests)
	}
}

func TestEvolveFallsBackWhenAgentTextIsNotJSON(t *testing.T) {
	moduleDir := t.TempDir()
	shellcode := filepath.Join(t.TempDir(), "agent.bin")
	if err := os.WriteFile(shellcode, []byte(strings.Repeat("X", 40000)), 0o600); err != nil {
		t.Fatal(err)
	}
	build := func(_ string, _ map[string]string) (string, error) {
		path := filepath.Join(t.TempDir(), "loader.exe")
		if err := os.WriteFile(path, []byte("MZ"+strings.Repeat("M", 40000)), 0o600); err != nil {
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
		Logf: nil,
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

func TestCheckExecutionUsesAgentStatus(t *testing.T) {
	noop := func(logging.Class, string, ...any) {}
	ctx := context.Background()

	e := &evolver{
		cfg:                   EvolveConfig{Stages: []string{"dynamic"}, Verify: &stubVerifyOps{}},
		expectedAgentUUID:     "loop-uuid",
		executionCheckTimeout: time.Millisecond,
		logf:                  noop,
	}
	execution, online, network := e.checkExecution(ctx, 0, true, nil)
	if execution != executionVerified || online == nil || !*online || network != 0 {
		t.Fatalf("online check = %q %v %d", execution, online, network)
	}

	e.cfg.Verify = &stubVerifyOps{offline: true}
	execution, online, _ = e.checkExecution(ctx, 0, true, nil)
	if execution != executionOffline || online == nil || *online {
		t.Fatalf("offline check = %q %v", execution, online)
	}

	e.cfg.Verify = nil
	execution, online, _ = e.checkExecution(ctx, 0, true, nil)
	if execution != executionUnverified || online != nil {
		t.Fatalf("unverified check = %q %v", execution, online)
	}

	execution, online, _ = e.checkExecution(ctx, 0, false, nil)
	if execution != executionStatic || online != nil {
		t.Fatalf("static check = %q %v", execution, online)
	}
}

func TestExecutionGateTracksExecutingCycles(t *testing.T) {
	noop := func(logging.Class, string, ...any) {}
	e := &evolver{logf: noop}
	ctx := context.Background()

	e.applyExecutionGate(ctx, &Cycle{Iteration: 1, PayloadKey: "sha256:first"}, cycleSummary{Execution: executionStatic})
	e.applyExecutionGate(ctx, &Cycle{Iteration: 2}, cycleSummary{Execution: executionUnverified})
	if e.lastExecuting != nil {
		t.Fatalf("lastExecuting = %+v", e.lastExecuting)
	}

	verified := &Cycle{Iteration: 3, PayloadKey: "sha256:running", Summary: `{"shellcode":"","producer":"donut"}`}
	e.applyExecutionGate(ctx, verified, cycleSummary{Execution: executionVerified})
	if e.lastExecuting != verified {
		t.Fatalf("lastExecuting = %+v", e.lastExecuting)
	}

	e.lastExecuting = nil
	e.applyExecutionGate(ctx, &Cycle{Iteration: 4}, cycleSummary{Execution: executionOffline})
	if !e.executionBlocked {
		t.Fatal("an offline cycle without an executing baseline must block further cycles")
	}
}

func TestExecutionGateRestoresLastExecutingPayload(t *testing.T) {
	moduleDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(moduleDir, "loader.c"), []byte("GOOD"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := newSourceRoots("loader_windows", sourceRoot{Name: "loader_windows", Dir: moduleDir, Writable: true})
	if err != nil {
		t.Fatal(err)
	}
	db, err := OpenTelemetryDB(filepath.Join(t.TempDir(), "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	insert := func(key string) int64 {
		res, err := db.db.ExecContext(ctx, `INSERT INTO payloads(payload_key, sha256, module, table_name)
			VALUES(?, ?, 'loader_windows', 'payload_view')`, key, strings.TrimPrefix(key, "sha256:"))
		if err != nil {
			t.Fatal(err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	goodID := insert("sha256:good")
	badID := insert("sha256:bad")
	if _, err := db.db.ExecContext(ctx, `INSERT INTO loop_edits(loop_id, iteration, payload_id, next_payload_id, module, file, old, new, reason)
		VALUES('loop', 2, ?, ?, 'loader_windows', 'loader.c', 'GOOD', 'BAD', 'cycle edit')`, goodID, badID); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "loader.c"), []byte("BAD"), 0o600); err != nil {
		t.Fatal(err)
	}
	goodShellcode := filepath.Join(t.TempDir(), "good.bin")
	if err := os.WriteFile(goodShellcode, []byte("GOOD-SHELLCODE"), 0o600); err != nil {
		t.Fatal(err)
	}
	badShellcode := filepath.Join(t.TempDir(), "bad.bin")
	if err := os.WriteFile(badShellcode, []byte("BAD-SHELLCODE"), 0o600); err != nil {
		t.Fatal(err)
	}
	summary, _ := json.Marshal(cycleSummary{Shellcode: goodShellcode, Producer: "donut"})
	e := &evolver{
		cfg: EvolveConfig{LoopID: "loop"}, db: db, roots: roots, iter: 2,
		last:           &Cycle{PayloadID: badID, PayloadKey: "sha256:bad"},
		lastExecuting:  &Cycle{PayloadID: goodID, PayloadKey: "sha256:good", Summary: string(summary)},
		shellcode:      badShellcode,
		activeProducer: "crystal_pack",
		logf:           func(logging.Class, string, ...any) {},
	}
	e.restoreExecutingState(ctx)

	content, err := os.ReadFile(filepath.Join(moduleDir, "loader.c"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "GOOD" {
		t.Fatalf("source was not restored: %q", content)
	}
	if e.shellcode != goodShellcode {
		t.Fatalf("shellcode = %q, want %q", e.shellcode, goodShellcode)
	}
	if e.activeProducer != "donut" {
		t.Fatalf("producer = %q, want donut", e.activeProducer)
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
	if err := os.WriteFile(shellcode, []byte(strings.Repeat("X", 40000)), 0o600); err != nil {
		t.Fatal(err)
	}
	build := func(_ string, _ map[string]string) (string, error) {
		path := filepath.Join(t.TempDir(), "loader.exe")
		if err := os.WriteFile(path, []byte("MZ"+strings.Repeat("M", 40000)), 0o600); err != nil {
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
		Logf: nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !strings.Contains(string(result.Answer), "recovered") {
		t.Fatalf("result = %+v", result)
	}
}

type captureProvider struct {
	answer   string
	requests []string
}

func (p *captureProvider) Stream(_ context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	p.requests = append(p.requests, fmt.Sprintf("%v", req.Messages))
	return func(yield func(llm.StreamEvent, error) bool) {
		if !yield(llm.StreamEvent{Type: llm.SEMessageStart}, nil) {
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: p.answer}, nil) {
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil) {
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func (p *captureProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(p.answer)}},
		"end_turn", llm.Usage{}, nil
}

func TestEvolveSendsBaselineFailureToModel(t *testing.T) {
	shellcode := filepath.Join(t.TempDir(), "agent.bin")
	if err := os.WriteFile(shellcode, []byte(strings.Repeat("S", 40000)), 0o600); err != nil {
		t.Fatal(err)
	}
	server, detonations := fakeEvolveSandbox(t)
	provider := &captureProvider{answer: `{"summary":"fixed the build","edits":[],"residual":[]}`}
	var (
		classMu sync.Mutex
		classes []logging.Class
	)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	_, err := RunEvolve(ctx, EvolveConfig{
		Provider: provider, Model: "scripted",
		Module: "loader_windows", ModuleDir: t.TempDir(), Shellcode: shellcode,
		SandboxURL: server.URL, StoreRoot: t.TempDir(), RetryBase: 50 * time.Millisecond,
		Stages: []string{"dynamic"}, Iterations: 1, Turns: 2,
		Build: func(string, map[string]string) (string, error) {
			return "compiler exploded", errors.New("simulated build failure")
		},
		Logf: func(class logging.Class, _ string, _ ...any) {
			classMu.Lock()
			classes = append(classes, class)
			classMu.Unlock()
		},
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the caller deadline; the loop must keep retrying", err)
	}
	if detonations.Load() != 0 {
		t.Fatalf("host detonated the payload again without model feedback: %d", detonations.Load())
	}
	if len(provider.requests) < 2 {
		t.Fatalf("model was not retried after the baseline failure: %v", provider.requests)
	}
	for _, want := range []string{"simulated build failure", "compiler exploded", "Baseline failure"} {
		if !strings.Contains(provider.requests[0], want) {
			t.Fatalf("first model prompt missing %q:\n%s", want, provider.requests[0])
		}
	}
	classMu.Lock()
	defer classMu.Unlock()
	for _, class := range classes {
		if class == logging.ClassModel {
			return
		}
	}
	t.Fatalf("model output was not logged after the baseline failure: %v", classes)
}

func TestEnsureFreshAgentRotatesAndCleansOldFiles(t *testing.T) {
	workspace := t.TempDir()
	storeRoot := filepath.Join(workspace, "detection")
	if err := os.MkdirAll(storeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	oldShellcode := filepath.Join(workspace, "old-agent.exe.bin")
	oldArtifact := filepath.Join(workspace, "old-agent.exe")
	if err := os.WriteFile(oldShellcode, []byte(strings.Repeat("S", 40000)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldArtifact, []byte(strings.Repeat("A", 40000)), 0o600); err != nil {
		t.Fatal(err)
	}
	producerDir := t.TempDir()
	config := `[{"name":"donut","build":"bash ./build.sh","is_local":true,"parameters":[
		{"name":"input","type":"string","required":true},
		{"name":"output","type":"string"}]}]`
	if err := os.WriteFile(filepath.Join(producerDir, "config.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	verify := &stubVerifyOps{}
	e := &evolver{
		cfg: EvolveConfig{
			LoopID: "loop-test", Module: "loader_windows", ModuleDir: t.TempDir(),
			Shellcode: oldShellcode, InitialAgentArtifact: oldArtifact,
			InitialShellcodeGenerated: true,
			StoreRoot:                 storeRoot, AgentType: "windows_executable",
			ProducerDirs: map[string]string{"donut": producerDir},
			BuildProducer: func(_ string, _ string, flags map[string]string) (string, error) {
				out := flags["output"]
				if err := os.WriteFile(out, []byte(strings.Repeat("P", 40000)), 0o600); err != nil {
					return "", err
				}
				return fmt.Sprintf("[+] generated payload: %s (40000 bytes)\n", out), nil
			},
			BuildAgent: func(AgentBuildOptions) (*AgentBuildResult, error) {
				path := filepath.Join(workspace, "new-agent.exe")
				if err := os.WriteFile(path, []byte(strings.Repeat("N", 40000)), 0o600); err != nil {
					return nil, err
				}
				return &AgentBuildResult{ArtifactPath: path, AgentUUID: "new-uuid", Size: 40000}, nil
			},
			Verify: verify,
		},
		logf:                      func(logging.Class, string, ...any) {},
		shellcode:                 oldShellcode,
		agentArtifact:             oldArtifact,
		initialShellcodeGenerated: true,
		activeProducer:            "donut",
		expectedAgentUUID:         "old-uuid",
		testedShellcodes:          map[string]struct{}{oldShellcode: {}},
		testedAgentUUIDs:          map[string]struct{}{"old-uuid": {}},
	}
	if err := e.ensureFreshAgent(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.expectedAgentUUID != "new-uuid" || e.agentArtifact == oldArtifact || e.shellcode == oldShellcode {
		t.Fatalf("agent was not rotated: uuid=%s artifact=%s shellcode=%s", e.expectedAgentUUID, e.agentArtifact, e.shellcode)
	}
	if len(verify.forgetCalls) != 1 || verify.forgetCalls[0] != "old-uuid" {
		t.Fatalf("old UUID was not forgotten: %v", verify.forgetCalls)
	}
	if _, err := os.Stat(oldShellcode); !os.IsNotExist(err) {
		t.Fatalf("old shellcode still exists: %v", err)
	}
	if _, err := os.Stat(oldArtifact); !os.IsNotExist(err) {
		t.Fatalf("old agent artifact still exists: %v", err)
	}
	if _, err := os.Stat(e.shellcode); err != nil {
		t.Fatalf("new shellcode missing: %v", err)
	}
	if _, err := os.Stat(e.agentArtifact); err != nil {
		t.Fatalf("new agent artifact missing: %v", err)
	}
}

func TestCheckExecutionHonorsOnlineLatch(t *testing.T) {
	e := &evolver{
		cfg:               EvolveConfig{Verify: &stubVerifyOps{offline: true}},
		expectedAgentUUID: "11111111-1111-1111-1111-111111111111",
	}
	var seen atomic.Bool
	seen.Store(true)
	state, online, _ := e.checkExecution(context.Background(), 0, true, &seen)
	if state != executionVerified || online == nil || !*online {
		t.Fatalf("state=%q online=%v, want verified online", state, online)
	}
	if !e.agentSeenOnline.Load() {
		t.Fatal("online latch was not recorded on the evolver")
	}
}

func TestRenderLoopReport(t *testing.T) {
	answer := map[string]any{
		"loop_id":         "loop-test",
		"summary":         "removed the verdict",
		"verdicts_before": []any{"Behavior:Win32/Test.A"},
		"verdicts_after":  []any{},
		"residual":        []any{".rdata entropy is inherent"},
		"git_dir":         "/tmp/git/loop-test",
		"git_heads":       map[string]string{"loader_windows": "0123456789abcdef0123456789abcdef01234567"},
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
		"## Source history", "loader_windows",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
}

// deadlineResumeProvider stalls the first session until the cycle deadline,
// answers on the retry, then cancels the loop to prove it kept running.
type deadlineResumeProvider struct {
	wait     time.Duration
	answer   string
	cancel   context.CancelFunc
	mu       sync.Mutex
	requests []string
}

func (p *deadlineResumeProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	p.mu.Lock()
	p.requests = append(p.requests, fmt.Sprintf("%v", req.Messages))
	n := len(p.requests)
	p.mu.Unlock()
	return func(yield func(llm.StreamEvent, error) bool) {
		switch {
		case n == 1:
			select {
			case <-ctx.Done():
				yield(llm.StreamEvent{}, ctx.Err())
			case <-time.After(p.wait):
				yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
			}
		case n == 2:
			if !yield(llm.StreamEvent{Type: llm.SEMessageStart}, nil) {
				return
			}
			if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: p.answer}, nil) {
				return
			}
			if !yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil) {
				return
			}
			yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
		default:
			p.cancel()
			yield(llm.StreamEvent{}, context.Canceled)
		}
	}
}

func (p *deadlineResumeProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{}, "", llm.Usage{}, nil
}

func TestEvolveResumesCycleAfterDeadline(t *testing.T) {
	moduleDir := t.TempDir()
	shellcode := filepath.Join(t.TempDir(), "agent.bin")
	if err := os.WriteFile(shellcode, []byte(strings.Repeat("S", 40000)), 0o600); err != nil {
		t.Fatal(err)
	}
	build := func(_ string, _ map[string]string) (string, error) {
		path := filepath.Join(t.TempDir(), "loader.exe")
		if err := os.WriteFile(path, []byte("MZ"+strings.Repeat("M", 40000)), 0o600); err != nil {
			return "", err
		}
		return fmt.Sprintf("[+] generated payload: %s (9 bytes)\n", path), nil
	}
	server, _ := fakeEvolveSandbox(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	provider := &deadlineResumeProvider{
		wait:   2 * time.Second,
		answer: `{"summary":"acted","edits":[],"residual":[]}`,
		cancel: cancel,
	}
	started := time.Now()
	_, err := RunEvolve(ctx, EvolveConfig{
		Provider: provider, Model: "scripted",
		Module: "loader_windows", ModuleDir: moduleDir,
		Shellcode: shellcode, SandboxURL: server.URL, StoreRoot: t.TempDir(),
		Stages: []string{"dynamic"}, Iterations: 2, Turns: 4, Build: build,
		CycleTimeout: 300 * time.Millisecond, ToolIdleTimeout: time.Hour,
		SessionTimeout: time.Hour, RetryBase: time.Millisecond,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("the cycle deadline did not stop the stalled session: %s", elapsed)
	}
	provider.mu.Lock()
	requests := append([]string(nil), provider.requests...)
	provider.mu.Unlock()
	if len(requests) != 3 {
		t.Fatalf("sessions = %d, want 3; the loop did not retry after the cycle deadline", len(requests))
	}
	for _, want := range []string{"cycle was stopped", "DetectionCycle"} {
		if !strings.Contains(requests[1], want) {
			t.Fatalf("retry prompt missing %q:\n%s", want, requests[1])
		}
	}
}

func TestEvolveForcesPlanAfterPlannerTimeout(t *testing.T) {
	moduleDir := t.TempDir()
	shellcode := filepath.Join(t.TempDir(), "agent.bin")
	if err := os.WriteFile(shellcode, []byte(strings.Repeat("S", 40000)), 0o600); err != nil {
		t.Fatal(err)
	}
	build := func(_ string, _ map[string]string) (string, error) {
		path := filepath.Join(t.TempDir(), "loader.exe")
		if err := os.WriteFile(path, []byte("MZ"+strings.Repeat("M", 40000)), 0o600); err != nil {
			return "", err
		}
		return fmt.Sprintf("[+] generated payload: %s (9 bytes)\n", path), nil
	}
	server, _ := fakeEvolveSandbox(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	provider := &deadlineResumeProvider{
		wait:   2 * time.Second,
		answer: `{"summary":"acted","edits":[],"residual":[]}`,
		cancel: cancel,
	}
	started := time.Now()
	_, err := RunEvolve(ctx, EvolveConfig{
		Provider: provider, Model: "scripted",
		Module: "loader_windows", ModuleDir: moduleDir,
		Shellcode: shellcode, SandboxURL: server.URL, StoreRoot: t.TempDir(),
		Stages: []string{"dynamic"}, Iterations: 2, Turns: 4, Build: build,
		PlannerTimeout: 300 * time.Millisecond, CycleTimeout: time.Hour,
		ToolIdleTimeout: time.Hour, SessionTimeout: time.Hour, RetryBase: time.Millisecond,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("the planner timeout did not stop the stalled session: %s", elapsed)
	}
	provider.mu.Lock()
	requests := append([]string(nil), provider.requests...)
	provider.mu.Unlock()
	if len(requests) != 3 {
		t.Fatalf("planner sessions = %d, want 3", len(requests))
	}
	for _, want := range []string{"decision window expired", "Return exactly one JSON plan"} {
		if !strings.Contains(requests[1], want) {
			t.Fatalf("forced-plan prompt missing %q:\n%s", want, requests[1])
		}
	}
}

func TestActionRequiredKeepsAnalysisToolsAvailable(t *testing.T) {
	e := &evolver{}
	e.actionRequired.Store(true)
	for _, name := range []string{
		"TelemetryQuery", "InspectFeedback", "Payloads", "ComparePayloads",
		"SourceRead", "EditSource", "DetectionCycle",
	} {
		if decision := e.allowToolHook(name); decision.Decision == "block" {
			t.Fatalf("%s was blocked while a cycle retry is required", name)
		}
	}
}

// countingAnswerProvider returns a non-JSON turn until the last session, where
// it cancels the loop. A stalled-restart cap would stop before that session.
type countingAnswerProvider struct {
	mu     sync.Mutex
	calls  int
	cancel context.CancelFunc
}

func (p *countingAnswerProvider) Stream(_ context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	p.mu.Lock()
	p.calls++
	n := p.calls
	p.mu.Unlock()
	return func(yield func(llm.StreamEvent, error) bool) {
		if n >= 6 {
			p.cancel()
			yield(llm.StreamEvent{}, context.Canceled)
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageStart}, nil) {
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "still thinking"}, nil) {
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil) {
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func (p *countingAnswerProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{}, "", llm.Usage{}, nil
}

func TestEvolveDoesNotStopAfterStalledSessions(t *testing.T) {
	moduleDir := t.TempDir()
	shellcode := filepath.Join(t.TempDir(), "agent.bin")
	if err := os.WriteFile(shellcode, []byte(strings.Repeat("S", 40000)), 0o600); err != nil {
		t.Fatal(err)
	}
	build := func(_ string, _ map[string]string) (string, error) {
		path := filepath.Join(t.TempDir(), "loader.exe")
		if err := os.WriteFile(path, []byte("MZ"+strings.Repeat("M", 40000)), 0o600); err != nil {
			return "", err
		}
		return fmt.Sprintf("[+] generated payload: %s (9 bytes)\n", path), nil
	}
	server, _ := fakeEvolveSandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	provider := &countingAnswerProvider{cancel: cancel}
	_, err := RunEvolve(ctx, EvolveConfig{
		Provider: provider, Model: "scripted",
		Module: "loader_windows", ModuleDir: moduleDir,
		Shellcode: shellcode, SandboxURL: server.URL, StoreRoot: t.TempDir(),
		Stages: []string{"dynamic"}, Iterations: 2, Turns: 4, Build: build,
		RetryBase: time.Millisecond, CycleTimeout: time.Hour,
		ToolIdleTimeout: time.Hour, SessionTimeout: time.Hour,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	provider.mu.Lock()
	calls := provider.calls
	provider.mu.Unlock()
	if calls != 6 {
		t.Fatalf("sessions = %d, want 6; the loop stopped on a stalled session", calls)
	}
}

func TestToolErrorResultLogsAsErrorClass(t *testing.T) {
	var classes []logging.Class
	e := &evolver{logf: func(class logging.Class, _ string, _ ...any) {
		classes = append(classes, class)
	}}
	hooks := e.hooks()
	hooks.PostToolUse(context.Background(), "EditSource", nil, []byte("save edit: edit has no payload"), true)
	hooks.PostToolUse(context.Background(), "SourceRead", nil, []byte("read 10 lines"), false)
	if len(classes) != 2 {
		t.Fatalf("log classes = %v", classes)
	}
	if classes[0] != logging.ClassError {
		t.Fatalf("failed tool result logged as %v, want ClassError", classes[0])
	}
	if classes[1] != logging.ClassToolResult {
		t.Fatalf("successful tool result logged as %v, want ClassToolResult", classes[1])
	}
}
