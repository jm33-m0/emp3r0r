package detection

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func TestWorkerToolPartition(t *testing.T) {
	e := &evolver{
		cfg:   EvolveConfig{Module: "loader_windows", ModuleDir: t.TempDir(), Verify: &stubVerifyOps{}},
		logf:  func(logging.Class, string, ...any) {},
		guest: &fakeGuestRunner{},
	}
	db, err := OpenTelemetryDB(filepath.Join(t.TempDir(), "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e.db = db
	e.roots = e.sourceRoots()
	e.cfg.Verify = &stubVerifyOps{}

	names := func(role evolveRole) map[string]bool {
		out := make(map[string]bool)
		for _, candidate := range e.toolsFor(role) {
			out[candidate.Name()] = true
		}
		return out
	}
	planner := names(rolePlanner)
	for _, want := range []string{"SourceRead", "TelemetryQuery", "AgentStatus", "KnowledgeSearch", "KnowledgeRead"} {
		if !planner[want] {
			t.Fatalf("planner is missing %s", want)
		}
	}
	for _, forbidden := range []string{"EditSource", "DetectionCycle", "BuildShellcode", "GuestSSH", "RunModule"} {
		if planner[forbidden] {
			t.Fatalf("planner has mutation or guest tool %s", forbidden)
		}
	}

	editor := names(roleEditor)
	for _, want := range []string{"EditSource", "DetectionCycle", "BuildShellcode", "RevertToPayload", "SourceRead"} {
		if !editor[want] {
			t.Fatalf("editor is missing %s", want)
		}
	}
	for _, forbidden := range []string{"GuestSSH", "RunModule", "AgentStatus"} {
		if editor[forbidden] {
			t.Fatalf("editor has debugger tool %s", forbidden)
		}
	}

	debugger := names(roleDebugger)
	for _, want := range []string{"GuestSSH", "AgentStatus", "RunModule", "CleanupAgent", "SourceRead"} {
		if !debugger[want] {
			t.Fatalf("debugger is missing %s", want)
		}
	}
	for _, forbidden := range []string{"EditSource", "DetectionCycle", "BuildShellcode", "RevertToPayload"} {
		if debugger[forbidden] {
			t.Fatalf("debugger has source tool %s", forbidden)
		}
	}
}

func mustRoots(t *testing.T, moduleDir string) *sourceRoots {
	t.Helper()
	roots, err := newSourceRoots("loader_windows", sourceRoot{Name: "loader_windows", Dir: moduleDir, Writable: true})
	if err != nil {
		t.Fatal(err)
	}
	return roots
}

func TestManualRelaunchDoesNotPromoteOfflineCycle(t *testing.T) {
	moduleDir := t.TempDir()
	source := filepath.Join(moduleDir, "loader.c")
	if err := os.WriteFile(source, []byte("BAD"), 0o600); err != nil {
		t.Fatal(err)
	}
	goodShellcode := filepath.Join(t.TempDir(), "good.bin")
	if err := os.WriteFile(goodShellcode, []byte("GOOD"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := OpenTelemetryDB(filepath.Join(t.TempDir(), "telemetry.db"))
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
	payloadID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	cycleResult, err := db.db.ExecContext(ctx, `INSERT INTO loop_cycles(loop_id, iteration, payload_id, run_id, execution, summary)
		VALUES('loop', 2, ?, 'run', 'offline', '{"execution":"offline"}')`, payloadID)
	if err != nil {
		t.Fatal(err)
	}
	cycleID, err := cycleResult.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.ExecContext(ctx, `INSERT INTO loop_edits(loop_id, iteration, payload_id, next_payload_id, module, file, old, new, reason)
		VALUES('loop', 2, ?, ?, 'loader_windows', 'loader.c', 'GOOD', 'BAD', 'cycle edit')`, payloadID, payloadID); err != nil {
		t.Fatal(err)
	}
	summary, _ := json.Marshal(cycleSummary{Shellcode: goodShellcode, Producer: "donut"})
	provider := &roleScriptProvider{scripts: map[string][]llm.Message{
		"debugger": {
			toolUseMessage("exclude-1", "GuestSSH", map[string]any{"action": "ensure_exclusion"}),
			toolUseMessage("status-1", "AgentStatus", map[string]any{}),
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
				llm.TextBlock(`{"cause":"the sandbox never launched the artifact; a manual launch checked in","evidence":["no loader process before manual launch"],"guest_actions":["started C:\\LitterBox\\Uploads\\loader.exe"],"agent_online_after":true,"source_fix_required":false,"confidence":"high"}`),
			}},
		},
	}}
	verify := &stubVerifyOps{}
	guest := &fakeGuestRunner{}
	e := &evolver{
		cfg: EvolveConfig{
			LoopID: "loop", Module: "loader_windows", ModuleDir: moduleDir,
			StoreRoot: t.TempDir(), Verify: verify, Turns: 4,
			DebuggerPolicy: debuggerPolicyCycle,
			Guest:          &GuestSSHConfig{Host: "127.0.0.1", Port: 2222, User: "litterbox", ExcludePath: guestStageDir},
		},
		db: db, roots: mustRoots(t, moduleDir), logf: func(logging.Class, string, ...any) {},
		guest:             guest,
		expectedAgentUUID: "uuid-1",
		shellcode:         filepath.Join(t.TempDir(), "bad.bin"),
		lastExecuting: &Cycle{
			PayloadID: payloadID, PayloadKey: "sha256:good", Summary: string(summary),
		},
	}
	badCycle := &Cycle{
		ID: cycleID, LoopID: "loop", Iteration: 2, PayloadID: payloadID,
		PayloadKey: "sha256:bad", Execution: executionOffline,
		Summary: `{"execution":"offline"}`,
	}
	e.last = badCycle
	c := newCoordinator(e, provider, "scripted", nil, "")
	if err := c.afterCycle(ctx, badCycle); err != nil {
		t.Fatal(err)
	}
	if badCycle.Execution != executionOffline {
		t.Fatalf("cycle execution = %q, want offline after a manual relaunch", badCycle.Execution)
	}
	if e.lastExecuting == badCycle {
		t.Fatal("a manually relaunched cycle became the execution baseline")
	}
	if !guest.excluded {
		t.Fatal("the debugger did not verify the guest exclusion")
	}
	if !strings.Contains(badCycle.Summary, `"recovered_by":"guest-debugger"`) {
		t.Fatalf("cycle summary missing the recovery record: %s", badCycle.Summary)
	}
	if !strings.Contains(badCycle.Summary, `"execution":"offline"`) {
		t.Fatalf("recovery rewrote the cycle execution: %s", badCycle.Summary)
	}
	workers, err := db.LoopWorkers(ctx, "loop", 10)
	if err != nil || len(workers) == 0 || workers[len(workers)-1].Role != string(roleDebugger) {
		t.Fatalf("worker runs = %+v err=%v", workers, err)
	}
	content, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "GOOD" {
		t.Fatalf("source was not restored to the clean baseline: %q", content)
	}
	var recorded string
	if err := db.db.QueryRow(`SELECT execution FROM loop_cycles WHERE id = ?`, cycleID).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != executionOffline {
		t.Fatalf("stored execution = %q, want offline", recorded)
	}
}

func TestDebuggerFailureRestoresNonExecutingCycle(t *testing.T) {
	moduleDir := t.TempDir()
	source := filepath.Join(moduleDir, "loader.c")
	if err := os.WriteFile(source, []byte("BAD"), 0o600); err != nil {
		t.Fatal(err)
	}
	goodShellcode := filepath.Join(t.TempDir(), "good.bin")
	if err := os.WriteFile(goodShellcode, []byte("GOOD"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := OpenTelemetryDB(filepath.Join(t.TempDir(), "telemetry.db"))
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
	payloadID, _ := res.LastInsertId()
	if _, err := db.db.ExecContext(ctx, `INSERT INTO loop_edits(loop_id, iteration, payload_id, next_payload_id, module, file, old, new, reason)
		VALUES('loop', 2, ?, ?, 'loader_windows', 'loader.c', 'GOOD', 'BAD', 'cycle edit')`, payloadID, payloadID); err != nil {
		t.Fatal(err)
	}
	summary, _ := json.Marshal(cycleSummary{Shellcode: goodShellcode, Producer: "donut"})
	provider := &roleScriptProvider{scripts: map[string][]llm.Message{
		"debugger": {
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
				llm.TextBlock(`{"cause":"the payload crashed before check-in","evidence":["WER dump"],"guest_actions":[],"agent_online_after":false,"source_fix_required":true,"editor_brief":"fix the crash","confidence":"medium"}`),
			}},
		},
	}}
	e := &evolver{
		cfg: EvolveConfig{
			LoopID: "loop", Module: "loader_windows", ModuleDir: moduleDir,
			StoreRoot: t.TempDir(), Verify: &stubVerifyOps{offline: true}, Turns: 4,
			DebuggerPolicy: debuggerPolicyCycle,
			Guest:          &GuestSSHConfig{Host: "127.0.0.1", Port: 2222, User: "litterbox", ExcludePath: guestStageDir},
		},
		db: db, roots: mustRoots(t, moduleDir), logf: func(logging.Class, string, ...any) {},
		guest:             &fakeGuestRunner{},
		expectedAgentUUID: "uuid-1",
		shellcode:         filepath.Join(t.TempDir(), "bad.bin"),
		lastExecuting: &Cycle{
			PayloadID: payloadID, PayloadKey: "sha256:good", Summary: string(summary),
		},
	}
	badCycle := &Cycle{ID: 2, LoopID: "loop", Iteration: 2, PayloadID: payloadID, PayloadKey: "sha256:bad", Execution: executionOffline, Summary: `{"execution":"offline"}`}
	e.last = badCycle
	c := newCoordinator(e, provider, "scripted", nil, "")
	if err := c.afterCycle(ctx, badCycle); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "GOOD" {
		t.Fatalf("source was not restored after a failed debug: %q", content)
	}
	if c.lastDiagnosis == nil || !strings.Contains(c.lastDiagnosis.Cause, "crashed") {
		t.Fatalf("diagnosis = %+v", c.lastDiagnosis)
	}
}

func TestParsePlannerPlan(t *testing.T) {
	plan, err := parsePlannerPlan(`{"action":"test","mechanism":"bogus","prediction":"x","editor_brief":"y"}`)
	if err != nil || plan.Action != "test" || plan.Mechanism != "other" {
		t.Fatalf("test plan = %+v err=%v", plan, err)
	}
	plan, err = parsePlannerPlan(`{"summary":"done","residual":[]}`)
	if err != nil || plan.Action != "stop" || plan.Final["summary"] != "done" {
		t.Fatalf("legacy final = %+v err=%v", plan, err)
	}
	plan, err = parsePlannerPlan("```json\n{\"action\":\"debug\",\"debug_focus\":\"check the upload\"}\n```")
	if err != nil || plan.Action != "debug" || plan.DebugFocus != "check the upload" {
		t.Fatalf("debug plan = %+v err=%v", plan, err)
	}
	if _, err := parsePlannerPlan(`{"action":"build"}`); err == nil {
		t.Fatal("unknown action was accepted")
	}
}

func TestParseDebugDiagnosis(t *testing.T) {
	diag, err := parseDebugDiagnosis(`{"cause":"never launched","evidence":["no process"],"guest_actions":["started the loader"],"agent_online_after":true,"source_fix_required":false,"confidence":"high"}`)
	if err != nil || diag.Cause != "never launched" || !diag.AgentOnlineAfter ||
		len(diag.Evidence) != 1 || len(diag.GuestActions) != 1 {
		t.Fatalf("diagnosis = %+v err=%v", diag, err)
	}
	if _, err := parseDebugDiagnosis(`{"confidence":"low"}`); err == nil {
		t.Fatal("a diagnosis without cause or evidence was accepted")
	}
}

func TestEditorDecisionWindowForcesRetry(t *testing.T) {
	moduleDir := t.TempDir()
	db, err := OpenTelemetryDB(filepath.Join(t.TempDir(), "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	roots, err := newSourceRoots("loader_windows", sourceRoot{Name: "loader_windows", Dir: moduleDir, Writable: true})
	if err != nil {
		t.Fatal(err)
	}
	e := &evolver{
		cfg: EvolveConfig{
			LoopID: "loop", Module: "loader_windows", ModuleDir: moduleDir,
			StoreRoot: t.TempDir(), Turns: 4, EditorTimeout: 200 * time.Millisecond,
			CycleTimeout: time.Hour, ToolIdleTimeout: time.Hour, SessionTimeout: time.Hour,
		},
		db: db, roots: roots, logf: func(logging.Class, string, ...any) {},
	}
	// Emulate a completed cycle so the editor Stop hook does not force another
	// turn; this test is only about the decision window.
	e.sessionCycles.Store(1)
	provider := &deadlineResumeProvider{wait: 2 * time.Second, answer: "done", cancel: func() {}}
	c := newCoordinator(e, provider, "scripted", nil, "")
	var reasons []string
	started := time.Now()
	text, err := c.runSession(context.Background(), roleEditor, "edit now", func(reason string) string {
		reasons = append(reasons, reason)
		return "retry"
	})
	if err != nil || text != "done" {
		t.Fatalf("runSession = %q err=%v", text, err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("the editor window did not cut the stalled session: %s", elapsed)
	}
	if len(reasons) != 1 || reasons[0] != "session" {
		t.Fatalf("resume reasons = %v", reasons)
	}
}

func TestDebuggerPolicyNormalization(t *testing.T) {
	dir := t.TempDir()
	shellcode := filepath.Join(dir, "agent.bin")
	if err := os.WriteFile(shellcode, []byte("SC"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := EvolveConfig{ModuleDir: dir, Shellcode: shellcode, StoreRoot: t.TempDir(), Stages: []string{"dynamic"}}
	for policy, want := range map[string]string{
		"":        debuggerPolicyFinal,
		"final":   debuggerPolicyFinal,
		"cycle":   debuggerPolicyCycle,
		"off":     debuggerPolicyOff,
		" CYCLE ": debuggerPolicyCycle,
	} {
		cfg := base
		cfg.DebuggerPolicy = policy
		if err := normalizeEvolveConfig(&cfg); err != nil {
			t.Fatalf("policy %q: %v", policy, err)
		}
		if cfg.DebuggerPolicy != want {
			t.Fatalf("policy %q normalized to %q, want %q", policy, cfg.DebuggerPolicy, want)
		}
	}
	cfg := base
	cfg.DebuggerPolicy = "sometimes"
	if err := normalizeEvolveConfig(&cfg); err == nil {
		t.Fatal("an unknown debugger policy was accepted")
	}
}

func TestVerifiedFindingRegressionKeepsBaseline(t *testing.T) {
	e := &evolver{logf: func(logging.Class, string, ...any) {}}
	e.lastExecuting = &Cycle{ID: 1, PayloadKey: "sha256:good", Findings: 10, Summary: `{"execution":"verified","high_findings":2,"static_findings":1}`}
	gate := e.recordExecution(&Cycle{ID: 2, PayloadKey: "sha256:worse", Findings: 10, Summary: `{"execution":"verified","high_findings":3,"static_findings":1}`},
		cycleSummary{Execution: executionVerified, HighFindings: 3, StaticFindings: 1})
	if gate != gateRegressed {
		t.Fatalf("gate = %v, want gateRegressed", gate)
	}
	if e.lastExecuting == nil || e.lastExecuting.ID != 1 {
		t.Fatalf("baseline was replaced by a worse cycle: %+v", e.lastExecuting)
	}
	gate = e.recordExecution(&Cycle{ID: 3, PayloadKey: "sha256:same", Findings: 10, Summary: `{"execution":"verified","high_findings":2,"static_findings":1}`},
		cycleSummary{Execution: executionVerified, HighFindings: 2, StaticFindings: 1})
	if gate != gateExecuting {
		t.Fatalf("gate = %v, want gateExecuting for equal findings", gate)
	}
	if e.lastExecuting == nil || e.lastExecuting.ID != 3 {
		t.Fatalf("an equal-findings cycle was not adopted: %+v", e.lastExecuting)
	}
	e.lastExecuting = &Cycle{ID: 4, Findings: 10, Summary: `{"execution":"verified","high_findings":0,"static_findings":0}`}
	gate = e.recordExecution(&Cycle{ID: 5, Findings: 10, Summary: `{"execution":"verified","high_findings":0,"static_findings":1}`},
		cycleSummary{Execution: executionVerified, HighFindings: 0, StaticFindings: 1})
	if gate != gateRegressed {
		t.Fatalf("gate = %v, want gateRegressed for a static-signature increase", gate)
	}
	counts := countFindings([]Finding{
		{Severity: "high", Stage: StageStatic},
		{Severity: "critical", Stage: StageDynamic},
		{Severity: "medium", Stage: StageStatic},
		{Severity: "low", Stage: StageTelemetry},
	})
	if counts.High != 2 || counts.Medium != 1 || counts.Static != 2 || counts.Total != 4 {
		t.Fatalf("finding counts = %+v, want high 2 medium 1 static 2 total 4", counts)
	}
}

func TestFinalDebuggerPolicyRunsOnePassAtStop(t *testing.T) {
	moduleDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(moduleDir, "loader.c"), []byte("int f(void){return 0;}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := OpenTelemetryDB(filepath.Join(t.TempDir(), "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	provider := &roleScriptProvider{scripts: map[string][]llm.Message{
		"debugger": {
			toolUseMessage("exclude-1", "GuestSSH", map[string]any{"action": "ensure_exclusion"}),
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
				llm.TextBlock(`{"cause":"the sandbox never launched the artifact","evidence":["no process"],"guest_actions":[],"agent_online_after":false,"source_fix_required":false,"confidence":"high"}`),
			}},
		},
	}}
	guest := &fakeGuestRunner{}
	e := &evolver{
		cfg: EvolveConfig{
			LoopID: "loop", Module: "loader_windows", ModuleDir: moduleDir,
			StoreRoot: t.TempDir(), Verify: &stubVerifyOps{offline: true}, Turns: 4,
			DebuggerPolicy: debuggerPolicyFinal,
			Guest:          &GuestSSHConfig{Host: "127.0.0.1", Port: 2222, User: "litterbox", ExcludePath: guestStageDir},
		},
		db: db, roots: mustRoots(t, moduleDir), logf: func(logging.Class, string, ...any) {},
		guest: guest, expectedAgentUUID: "uuid-1",
	}
	e.last = &Cycle{ID: 9, LoopID: "loop", Iteration: 3, Execution: executionOffline, Summary: `{"execution":"offline"}`}
	c := newCoordinator(e, provider, "scripted", nil, "")
	if c.debuggerAvailableFor(e.last) {
		t.Fatal("the final policy exposed the debugger in the cycle loop")
	}
	if reason := c.debuggerUnavailableReason(); !strings.Contains(reason, "final stop") {
		t.Fatalf("unavailable reason = %q", reason)
	}
	final := map[string]any{"summary": "stopped"}
	c.finalDiagnosis(context.Background(), final)
	if c.debuggerSessions != 1 {
		t.Fatalf("debugger sessions = %d, want 1", c.debuggerSessions)
	}
	if final["debugger_diagnosis"] == nil {
		t.Fatal("the final answer has no debugger diagnosis")
	}
	residual := answerStrings(final, "residual")
	if len(residual) == 0 || !strings.Contains(residual[0], "final debugger") {
		t.Fatalf("residual = %v", residual)
	}
	c.finalDiagnosis(context.Background(), final)
	if c.debuggerSessions != 1 {
		t.Fatalf("the final pass repeated: %d sessions", c.debuggerSessions)
	}
}

func TestRepeatedNonImprovingMechanism(t *testing.T) {
	mk := func(mechanism string, high, static, total int, execution string, verdicts int) Cycle {
		summary, _ := json.Marshal(cycleSummary{Mechanism: mechanism, Execution: execution, HighFindings: high, StaticFindings: static})
		return Cycle{Findings: total, Execution: execution, Verdicts: verdicts, Summary: string(summary)}
	}
	cases := []struct {
		name      string
		cycles    []Cycle
		candidate string
		want      bool
	}{
		{"different mechanisms", []Cycle{mk("module-stomp", 1, 0, 10, executionVerified, 0), mk("section-map", 1, 0, 10, executionVerified, 0)}, "section-map", false},
		{"same mechanism, equal findings", []Cycle{mk("producer", 1, 0, 10, executionVerified, 0), mk("producer", 1, 0, 10, executionVerified, 0)}, "producer", true},
		{"same mechanism, fewer high", []Cycle{mk("producer", 1, 0, 10, executionVerified, 0), mk("producer", 0, 0, 10, executionVerified, 0)}, "producer", false},
		{"same mechanism, fewer static", []Cycle{mk("producer", 1, 1, 10, executionVerified, 0), mk("producer", 1, 0, 10, executionVerified, 0)}, "producer", false},
		{"same mechanism, fewer verdicts", []Cycle{mk("producer", 1, 0, 10, executionVerified, 2), mk("producer", 1, 0, 10, executionVerified, 1)}, "producer", false},
		{"same mechanism, offline", []Cycle{mk("producer", 1, 0, 10, executionOffline, 0), mk("producer", 1, 0, 10, executionOffline, 0)}, "producer", true},
	}
	for _, tc := range cases {
		e := &evolver{cycles: tc.cycles, logf: func(logging.Class, string, ...any) {}}
		c := newCoordinator(e, &roleScriptProvider{}, "scripted", nil, "")
		if got := c.repeatedNonImprovingMechanism(tc.candidate); got != tc.want {
			t.Fatalf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func writeProducerModuleConfig(t *testing.T, name, input string) string {
	t.Helper()
	dir := t.TempDir()
	body, err := json.Marshal([]map[string]any{{
		"name": name, "build": "true", "is_local": true,
		"parameters": []map[string]any{{"name": input, "type": "string", "required": true}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRotationAgentTypeFollowsProducer(t *testing.T) {
	e := &evolver{
		cfg: EvolveConfig{
			AgentType: "windows_executable",
			ProducerDirs: map[string]string{
				"crystal_pack": writeProducerModuleConfig(t, "crystal_pack", "dll"),
				"donut":        writeProducerModuleConfig(t, "donut", "input"),
			},
		},
		activeProducer: "crystal_pack",
	}
	if got := e.rotationAgentType(); got != "windows_dll" {
		t.Fatalf("crystal_pack rotation type = %q, want windows_dll", got)
	}
	e.activeProducer = "donut"
	if got := e.rotationAgentType(); got != "windows_executable" {
		t.Fatalf("donut rotation type = %q, want windows_executable", got)
	}
	e.cfg.AgentType = "auto"
	if got := e.rotationAgentType(); got != "windows_executable" {
		t.Fatalf("auto rotation type = %q, want windows_executable", got)
	}
	e.cfg.AgentType = "windows_dll"
	if got := e.rotationAgentType(); got != "windows_dll" {
		t.Fatalf("dll rotation type = %q, want windows_dll", got)
	}
}

// failingEditorProvider returns a valid plan but fails every editor call, like
// a terminal provider rejection. The coordinator must stop after its
// infrastructure budget instead of retrying the same plan until the plan cap.
type failingEditorProvider struct {
	planner     string
	editorCalls int
}

func (p *failingEditorProvider) Stream(_ context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	role := workerRole(req)
	return func(yield func(llm.StreamEvent, error) bool) {
		if role == "editor" {
			p.editorCalls++
			yield(llm.StreamEvent{}, errors.New("provider unavailable"))
			return
		}
		emitScriptedMessage(yield, llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
			llm.TextBlock(p.planner),
		}})
	}
}

func (p *failingEditorProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{}, "", llm.Usage{}, nil
}

func TestEditorInfrastructureFailuresStopTheLoop(t *testing.T) {
	moduleDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(moduleDir, "loader.c"), []byte("int f(void){return 0;}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := &failingEditorProvider{planner: `{"action":"test","mechanism":"other","prediction":"x","editor_brief":"y"}`}
	e := &evolver{
		cfg: EvolveConfig{
			LoopID: "loop", Module: "loader_windows", ModuleDir: moduleDir,
			StoreRoot: t.TempDir(), Iterations: 5, Turns: 4,
			RetryBase: time.Millisecond, EditorTimeout: time.Hour,
			ToolIdleTimeout: time.Hour, SessionTimeout: time.Hour,
		},
		roots: mustRoots(t, moduleDir), logf: func(logging.Class, string, ...any) {},
	}
	c := newCoordinator(e, provider, "scripted", nil, "")
	final, err := c.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary := answerString(final, "summary"); !strings.Contains(summary, "editor worker") {
		t.Fatalf("final summary = %q", summary)
	}
	if c.plans > 6 {
		t.Fatalf("coordinator plans = %d; the infrastructure budget did not stop the retry loop", c.plans)
	}
	// Three editor steps, each retried by the session budget.
	if provider.editorCalls > 20 {
		t.Fatalf("editor model calls = %d; the retry budget was reset", provider.editorCalls)
	}
}
