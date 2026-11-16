package detection

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func TestLoadAttemptStateCarriesPriorAttempt(t *testing.T) {
	db, err := OpenTelemetryDB(filepath.Join(t.TempDir(), "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	res, err := db.db.Exec(`INSERT INTO payloads(payload_key, sha256, module, table_name)
		VALUES('sha256:prior', 'prior', 'loader_windows', 'payload_prior')`)
	if err != nil {
		t.Fatal(err)
	}
	payloadID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	for _, cycle := range []Cycle{
		{LoopID: "loop", Iteration: 1, PayloadID: payloadID, Execution: executionVerified, Executed: true},
		{LoopID: "loop", Iteration: 2, PayloadID: payloadID, Execution: executionOffline},
		{LoopID: "loop-r1", Iteration: 1, PayloadID: payloadID, Execution: executionVerified, Executed: true},
	} {
		if _, err := db.SaveCycle(ctx, cycle); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.db.Exec(`INSERT INTO loop_results(loop_id, answer, report, created_at)
		VALUES('loop', '{"summary":"prior summary","residual":["prior residual"],"source_tree_hash":"sha256:old","expected_agent_uuid":"uuid-prior"}', '', 1000)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`INSERT INTO loop_edits(loop_id, iteration, payload_id, module, file, old, new, reason, created_at)
		VALUES('loop', 3, ?, 'loader_windows', 'build.sh', 'a', 'b', 'revert to payload sha256:prior', 2000)`, payloadID); err != nil {
		t.Fatal(err)
	}

	e := &evolver{
		cfg:              EvolveConfig{LoopID: "loop-r2", BaseLoopID: "loop", Attempt: 2, Iterations: 20, Module: "loader_windows"},
		db:               db,
		baseLoopID:       "loop",
		attempt:          2,
		testedAgentUUIDs: make(map[string]struct{}),
		testedShellcodes: make(map[string]struct{}),
		logf:             func(class logging.Class, format string, args ...any) {},
		roots:            newSingleRoot(t.TempDir()),
	}
	if err := e.loadAttemptState(ctx); err != nil {
		t.Fatal(err)
	}
	if e.globalUsed != 3 {
		t.Fatalf("globalUsed = %d, want 3", e.globalUsed)
	}
	if e.priorLastGood == nil || e.priorLastGood.LoopID != "loop-r1" {
		t.Fatalf("priorLastGood = %+v, want last verified r1 cycle", e.priorLastGood)
	}
	if got := answerString(e.priorAnswer, "summary"); got != "prior summary" {
		t.Fatalf("prior summary = %q", got)
	}
	if len(e.pendingEdits) != 1 || e.pendingEdits[0].File != "build.sh" {
		t.Fatalf("pending edits = %+v", e.pendingEdits)
	}
	if _, ok := e.testedAgentUUIDs["uuid-prior"]; !ok {
		t.Fatal("prior expected agent UUID was not seeded")
	}

	dossier := e.dossier()
	for _, want := range []string{
		"logical loop: loop; attempt 2 (r2)",
		"cycles used: 3 of 20 global",
		"prior attempt summary: prior summary",
		"pending revert: loader_windows/build.sh",
		"attempt 1 cycle 2 (global 2)",
	} {
		if !strings.Contains(dossier, want) {
			t.Fatalf("dossier missing %q:\n%s", want, dossier)
		}
	}
}

func TestRunCycleRejectsExhaustedGlobalBudget(t *testing.T) {
	e := &evolver{cfg: EvolveConfig{Iterations: 20}, globalUsed: 20}
	if _, err := e.runCycle(context.Background(), "baseline", "baseline", ""); !errors.Is(err, ErrCycleBudgetExhausted) {
		t.Fatalf("runCycle error = %v, want budget exhausted", err)
	}
}

func TestSourceTreeHashTracksEditableSource(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "loader.c")
	if err := os.WriteFile(source, []byte("int main(void){return 0;}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &evolver{roots: newSingleRoot(dir)}
	first := e.computeSourceTreeHash()
	if !strings.HasPrefix(first, "sha256:") {
		t.Fatalf("hash = %q", first)
	}
	if err := os.WriteFile(source, []byte("int main(void){return 1;}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second := e.computeSourceTreeHash()
	if second == first {
		t.Fatalf("hash did not change after source edit: %q", first)
	}
}

func TestResidualCoversActionableFindings(t *testing.T) {
	actionable := Finding{
		Stage: StageTelemetry, Severity: "medium", Rule: "telemetry/user-module",
		Indicator: "RedEdrDll.dll", Sources: []SourceLocation{{File: "telemetry.go"}},
	}
	e := &evolver{lastAnswer: map[string]any{
		"residual": []any{"ambient telemetry/user-module RedEdrDll.dll comes from the sandbox"},
	}}
	if !e.residualCovers([]Finding{actionable}) {
		t.Fatal("residual naming the actionable finding was not accepted")
	}
	e.lastAnswer = map[string]any{"residual": []any{"a different module"}}
	if e.residualCovers([]Finding{actionable}) {
		t.Fatal("residual that does not name the finding was accepted")
	}
	e.lastAnswer = map[string]any{"residual": []any{}}
	if e.residualCovers([]Finding{actionable}) {
		t.Fatal("empty residual covered an actionable finding")
	}
}
