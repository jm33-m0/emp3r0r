package detection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func TestResilientProviderRetriesEmptyResponse(t *testing.T) {
	next := &emptyThenTextProvider{text: `{"action":"stop","final":{"summary":"done"}}`}
	provider := &resilientProvider{next: next, logf: func(logging.Class, string, ...any) {}}
	var text strings.Builder
	for event, err := range provider.Stream(context.Background(), llm.CompletionRequest{}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Type == llm.SETextDelta {
			text.WriteString(event.Text)
		}
	}
	if next.calls != 2 {
		t.Fatalf("calls = %d, want 2 after an empty response", next.calls)
	}
	if !strings.Contains(text.String(), `"summary":"done"`) {
		t.Fatalf("text = %q", text.String())
	}
}

type emptyThenTextProvider struct {
	calls int
	text  string
}

func (p *emptyThenTextProvider) Stream(_ context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	p.calls++
	n := p.calls
	return func(yield func(llm.StreamEvent, error) bool) {
		if !yield(llm.StreamEvent{Type: llm.SEMessageStart}, nil) {
			return
		}
		if n > 1 {
			if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: p.text}, nil) {
				return
			}
			if !yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil) {
				return
			}
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func (p *emptyThenTextProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{}, "", llm.Usage{}, nil
}

func TestStopHooksEnforceWorkerContracts(t *testing.T) {
	e := &evolver{logf: func(logging.Class, string, ...any) {}}
	ctx := context.Background()
	answer := func(text string) []llm.Message {
		return []llm.Message{{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(text)}}}
	}

	e.sessionCycles.Store(0)
	if prevent, blocking, _ := e.hooksFor(roleEditor).Stop(ctx, answer("done")); prevent || len(blocking) != 1 {
		t.Fatalf("editor stop without a cycle: prevent=%v blocking=%v", prevent, blocking)
	}
	e.sessionCycles.Store(1)
	if prevent, blocking, _ := e.hooksFor(roleEditor).Stop(ctx, answer("done")); prevent || len(blocking) != 0 {
		t.Fatalf("editor stop after a cycle: prevent=%v blocking=%v", prevent, blocking)
	}

	if _, blocking, _ := e.hooksFor(rolePlanner).Stop(ctx, answer("not json")); len(blocking) != 1 {
		t.Fatalf("planner invalid JSON was not blocked: %v", blocking)
	}
	if _, blocking, _ := e.hooksFor(rolePlanner).Stop(ctx, answer(`{"action":"stop","final":{"summary":"x"}}`)); len(blocking) != 0 {
		t.Fatalf("valid planner JSON was blocked: %v", blocking)
	}

	if _, blocking, _ := e.hooksFor(roleDebugger).Stop(ctx, answer("not json")); len(blocking) != 1 {
		t.Fatalf("debugger invalid JSON was not blocked: %v", blocking)
	}
}

func TestEditorReadBudgetBlocksFurtherReading(t *testing.T) {
	moduleDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(moduleDir, "selfload.c"), []byte("void f(void) {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := OpenTelemetryDB(filepath.Join(t.TempDir(), "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := &evolver{
		cfg: EvolveConfig{Module: "loader_windows", ModuleDir: moduleDir, StoreRoot: t.TempDir()},
		db:  db, roots: mustRoots(t, moduleDir),
		logf: func(logging.Class, string, ...any) {},
	}
	hooks := e.hooksFor(roleEditor)
	read := []byte(`{"path":"selfload.c"}`)
	for i := range editorReadBudget {
		if blocked, message, _ := hooks.PreToolUse(context.Background(), "SourceRead", read); blocked {
			t.Fatalf("read %d was blocked early: %s", i+1, message)
		}
	}
	blocked, message, _ := hooks.PreToolUse(context.Background(), "SourceRead", read)
	if !blocked || !strings.Contains(message, "read budget") {
		t.Fatalf("read budget did not block: blocked=%v message=%q", blocked, message)
	}
	if blocked, _, _ := hooks.PreToolUse(context.Background(), "EditSource", []byte(`{}`)); blocked {
		t.Fatal("the read budget blocked a mutation")
	}
}

func TestDebuggerOnePassPerCycleAndBudget(t *testing.T) {
	moduleDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(moduleDir, "selfload.c"), []byte("void f(void) {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := OpenTelemetryDB(filepath.Join(t.TempDir(), "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	provider := &roleScriptProvider{scripts: map[string][]llm.Message{
		"debugger": {
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
				llm.TextBlock(`{"cause":"never launched","evidence":["no process"],"agent_online_after":false,"source_fix_required":true,"editor_brief":"fix the launch","confidence":"high"}`),
			}},
		},
	}}
	e := &evolver{
		cfg: EvolveConfig{
			LoopID: "loop", Module: "loader_windows", ModuleDir: moduleDir,
			StoreRoot: t.TempDir(), Iterations: 4, Turns: 4,
		},
		db: db, roots: mustRoots(t, moduleDir), logf: func(logging.Class, string, ...any) {},
		guest: &fakeGuestRunner{},
	}
	c := newCoordinator(e, provider, "scripted", nil, "")
	cycle := &Cycle{ID: 7, LoopID: "loop", Iteration: 1, PayloadKey: "sha256:bad", Execution: executionOffline}
	if !c.debuggerAvailableFor(cycle) {
		t.Fatal("the first debugger pass should be available")
	}
	if _, err := c.debug(context.Background(), debugRequest{Trigger: "test", Cycle: cycle}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.debug(context.Background(), debugRequest{Trigger: "again", Cycle: cycle}); err == nil ||
		!strings.Contains(err.Error(), "already debugged") {
		t.Fatalf("second pass for one cycle: %v", err)
	}
	c.debuggerSessions = c.debuggerBudget()
	if _, err := c.debug(context.Background(), debugRequest{Trigger: "budget", Cycle: &Cycle{ID: 8, Iteration: 2}}); err == nil ||
		!strings.Contains(err.Error(), "limit reached") {
		t.Fatalf("budget was not enforced: %v", err)
	}
}

func TestSourceRootsAcceptModulePrefixedPaths(t *testing.T) {
	base := t.TempDir()
	moduleDir := filepath.Join(base, "module")
	producerDir := filepath.Join(base, "donut")
	for _, dir := range []string{moduleDir, producerDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "selfload.c"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(producerDir, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := newSourceRoots("module",
		sourceRoot{Name: "module", Dir: moduleDir, Writable: true},
		sourceRoot{Name: "donut", Dir: producerDir, Writable: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ module, path string }{
		{"", "module/selfload.c"},
		{"module", "module/selfload.c"},
		{"", "donut/config.json"},
	} {
		root, path, err := roots.resolve(tc.module, tc.path)
		if err != nil {
			t.Fatalf("resolve %s/%s: %v", tc.module, tc.path, err)
		}
		if !strings.HasSuffix(path, filepath.Base(tc.path)) {
			t.Fatalf("resolve %s/%s = %s", tc.module, tc.path, path)
		}
		_ = root
	}
}

func TestTelemetryQueryErrorListsColumns(t *testing.T) {
	db, err := OpenTelemetryDB(filepath.Join(t.TempDir(), "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, queryErr := db.Query(context.Background(), "SELECT attrs FROM findings", 10)
	if queryErr == nil {
		t.Fatal("expected the unknown-column error")
	}
	hint := db.explainQueryError(context.Background(), "SELECT attrs FROM findings", queryErr)
	for _, want := range []string{"findings columns:", "attrs", "findings has no attrs"} {
		if !strings.Contains(hint, want) {
			t.Fatalf("hint missing %q:\n%s", want, hint)
		}
	}
}

func TestRestorePreservesLastExecutingShellcode(t *testing.T) {
	storeRoot := t.TempDir()
	path := filepath.Join(storeRoot, "shellcode", "last-good.bin")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("GOOD"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &evolver{
		cfg:  EvolveConfig{StoreRoot: storeRoot},
		logf: func(logging.Class, string, ...any) {},
	}
	e.setPreservedShellcode(path)
	e.cleanupShellcode(path)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("preserved shellcode was deleted: %v", err)
	}
}

func TestRestoreRecordsRollbackSeparately(t *testing.T) {
	base := t.TempDir()
	moduleDir := filepath.Join(base, "module")
	if err := os.MkdirAll(moduleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(moduleDir, "selfload.c")
	if err := os.WriteFile(source, []byte("BAD"), 0o600); err != nil {
		t.Fatal(err)
	}
	goodShellcode := filepath.Join(base, "good.bin")
	if err := os.WriteFile(goodShellcode, []byte("GOOD"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := OpenTelemetryDB(filepath.Join(base, "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	res, err := db.db.ExecContext(ctx, `INSERT INTO payloads(payload_key, sha256, module, table_name)
		VALUES('sha256:bad', 'bad', 'loader_windows', 'payload_bad')`)
	if err != nil {
		t.Fatal(err)
	}
	badID, _ := res.LastInsertId()
	goodRes, err := db.db.ExecContext(ctx, `INSERT INTO payloads(payload_key, sha256, module, table_name)
		VALUES('sha256:good', 'good', 'loader_windows', 'payload_good')`)
	if err != nil {
		t.Fatal(err)
	}
	goodID, _ := goodRes.LastInsertId()
	if _, err := db.db.ExecContext(ctx, `INSERT INTO loop_edits(loop_id, iteration, payload_id, next_payload_id, module, file, old, new, reason, kind)
		VALUES('loop', 2, ?, ?, 'loader_windows', 'selfload.c', 'GOOD', 'BAD', 'cycle edit', 'model')`, badID, badID); err != nil {
		t.Fatal(err)
	}
	summary, _ := json.Marshal(cycleSummary{Shellcode: goodShellcode, Producer: "donut"})
	e := &evolver{
		cfg: EvolveConfig{LoopID: "loop", ModuleDir: moduleDir, StoreRoot: base},
		db:  db, roots: mustRoots(t, moduleDir), logf: func(logging.Class, string, ...any) {},
		shellcode: "/missing/bad.bin",
		last:      &Cycle{ID: 2, LoopID: "loop", Iteration: 2, PayloadID: badID, PayloadKey: "sha256:bad"},
		lastExecuting: &Cycle{
			ID: 1, LoopID: "loop", Iteration: 1, PayloadID: goodID, PayloadKey: "sha256:good",
			Summary: string(summary),
		},
	}
	if err := e.restoreExecutingState(ctx); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "GOOD" {
		t.Fatalf("source was not restored: %q", data)
	}
	var kind string
	var next any
	if err := db.db.QueryRow(`SELECT kind, next_payload_id FROM loop_edits ORDER BY id DESC LIMIT 1`).Scan(&kind, &next); err != nil {
		t.Fatal(err)
	}
	if kind != EditKindRestore || next != nil {
		t.Fatalf("rollback record kind=%q next=%v", kind, next)
	}
	edits, err := db.EditsForPayload(ctx, "sha256:bad")
	if err != nil {
		t.Fatal(err)
	}
	if len(edits) != 1 || edits[0].Kind != EditKindModel {
		t.Fatalf("payload edits = %+v", edits)
	}
}

func TestEvolveRetriesEmptyEditorTurn(t *testing.T) {
	result, source := runEditorScriptLoop(t, []llm.Message{
		{}, // a completed turn with no text and no tool call
		toolUseMessage("edit-empty", "EditSource", map[string]any{
			"file": "bootstrap.c", "old_string": "OLD", "new_string": "NEW", "reason": "retry the empty turn",
		}),
		toolUseMessage("cycle-empty", "DetectionCycle", map[string]any{"mechanism": "self-load"}),
	})
	if len(result.Cycles) != 2 {
		t.Fatalf("cycles = %d, want baseline plus one edited cycle", len(result.Cycles))
	}
	if !strings.Contains(source, "NEW") {
		t.Fatalf("the retried editor turn did not apply the edit: %q", source)
	}
}

func TestEvolveForcesEditorCycleWithStopHook(t *testing.T) {
	result, source := runEditorScriptLoop(t, []llm.Message{
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("nothing to do")}},
		toolUseMessage("edit-stop", "EditSource", map[string]any{
			"file": "bootstrap.c", "old_string": "OLD", "new_string": "NEW", "reason": "stop hook forced the cycle",
		}),
		toolUseMessage("cycle-stop", "DetectionCycle", map[string]any{"mechanism": "self-load"}),
	})
	if len(result.Cycles) != 2 {
		t.Fatalf("cycles = %d, want baseline plus one edited cycle", len(result.Cycles))
	}
	if !strings.Contains(source, "NEW") {
		t.Fatalf("the forced editor turn did not apply the edit: %q", source)
	}
}

func runEditorScriptLoop(t *testing.T, editor []llm.Message) (*EvolveResult, string) {
	t.Helper()
	moduleDir := t.TempDir()
	sourcePath := filepath.Join(moduleDir, "bootstrap.c")
	if err := os.WriteFile(sourcePath, []byte("const char *process = \"OLD\";\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	build := func(_ string, _ map[string]string) (string, error) {
		path := filepath.Join(t.TempDir(), "loader.exe")
		if err := os.WriteFile(path, []byte("MZ"+strings.Repeat("M", 40000)), 0o600); err != nil {
			return "", err
		}
		return fmt.Sprintf("[+] generated payload: %s (9 bytes)\n", path), nil
	}
	shellcode := filepath.Join(t.TempDir(), "agent.bin")
	if err := os.WriteFile(shellcode, []byte(strings.Repeat("S", 40000)), 0o600); err != nil {
		t.Fatal(err)
	}
	server, _ := fakeEvolveSandbox(t)
	provider := &roleScriptProvider{scripts: map[string][]llm.Message{
		"planner": {
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
				llm.TextBlock(`{"action":"test","mechanism":"self-load","editor_brief":"change the default in bootstrap.c","reason":"test"}`),
			}},
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
				llm.TextBlock(`{"action":"stop","final":{"summary":"done","residual":[]}}`),
			}},
		},
		"editor": editor,
	}}
	result, err := RunEvolve(context.Background(), EvolveConfig{
		Provider: provider, Model: "scripted",
		Module: "loader_windows", ModuleDir: moduleDir,
		Shellcode: shellcode, SandboxURL: server.URL, StoreRoot: t.TempDir(),
		Stages: []string{"dynamic"}, Iterations: 2, Turns: 8, Build: build,
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	return result, string(data)
}

func TestInfrastructureFailureClassification(t *testing.T) {
	if !isInfrastructureFailure(fmt.Errorf("%w: empty", errWorkerEmpty)) {
		t.Fatal("empty worker failure was not infrastructure")
	}
	if !isInfrastructureFailure(fmt.Errorf("%w: restarts", errSessionRestarts)) {
		t.Fatal("session restart failure was not infrastructure")
	}
	if !isInfrastructureFailure(fmt.Errorf("%w: cycle", errCycleInfrastructure)) {
		t.Fatal("host cycle failure was not infrastructure")
	}
	if !isInfrastructureFailure(fmt.Errorf("%w: health", ErrSandboxUnreachable)) {
		t.Fatal("sandbox outage was not infrastructure")
	}
	if isInfrastructureFailure(errors.New("the editor returned without running DetectionCycle")) {
		t.Fatal("contract failure was treated as infrastructure")
	}
}
