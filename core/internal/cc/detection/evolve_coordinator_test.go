package detection

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	for _, want := range []string{"SourceRead", "TelemetryQuery", "AgentStatus"} {
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

func TestDebuggerRecoversOfflineCycleBeforeRestore(t *testing.T) {
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
			Guest: &GuestSSHConfig{Host: "127.0.0.1", Port: 2222, User: "litterbox", ExcludePath: guestStageDir},
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
	c := newCoordinator(e, provider, "scripted", nil, "", "")
	if err := c.afterCycle(ctx, badCycle); err != nil {
		t.Fatal(err)
	}
	if badCycle.Execution != executionVerified {
		t.Fatalf("cycle execution = %q, want verified", badCycle.Execution)
	}
	if e.lastExecuting != badCycle {
		t.Fatal("recovered cycle was not recorded as the last executing payload")
	}
	if !guest.excluded {
		t.Fatal("the debugger did not verify the guest exclusion")
	}
	if !strings.Contains(badCycle.Summary, `"recovered_by":"guest-debugger"`) {
		t.Fatalf("cycle summary missing the recovery record: %s", badCycle.Summary)
	}
	workers, err := db.LoopWorkers(ctx, "loop", 10)
	if err != nil || len(workers) == 0 || workers[len(workers)-1].Role != string(roleDebugger) {
		t.Fatalf("worker runs = %+v err=%v", workers, err)
	}
	content, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "BAD" {
		t.Fatalf("source was restored before the debugger ran: %q", content)
	}
	var recorded string
	if err := db.db.QueryRow(`SELECT execution FROM loop_cycles WHERE id = ?`, cycleID).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != executionVerified {
		t.Fatalf("stored execution = %q", recorded)
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
			Guest: &GuestSSHConfig{Host: "127.0.0.1", Port: 2222, User: "litterbox", ExcludePath: guestStageDir},
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
	c := newCoordinator(e, provider, "scripted", nil, "", "")
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
