package detection

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func TestLoopMemoryRecordsAndQueriesVerifiedTechnique(t *testing.T) {
	db, err := OpenTelemetryDB(filepath.Join(t.TempDir(), "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()

	previous := cycleSummary{
		Execution:      executionVerified,
		HighFindings:   1,
		StaticFindings: 2,
		TopFindings:    []string{"high pe/checksum PE checksum"},
		Telemetry:      &TelemetryStats{Coverage: TelemetryCoverage{Delivered: []string{"etw", "kernel"}}},
	}
	encoded, err := json.Marshal(previous)
	if err != nil {
		t.Fatal(err)
	}
	e := &evolver{
		cfg:  EvolveConfig{LoopID: "loop-memory"},
		db:   db,
		logf: func(logging.Class, string, ...any) {},
	}
	e.cycles = []Cycle{{ID: 1, LoopID: "loop-memory", Iteration: 1, Execution: executionVerified, Summary: string(encoded)}}
	e.lastComparable = &e.cycles[0]
	e.lastExecuting = &e.cycles[0]

	if err := db.SaveEdit(ctx, EditRecord{
		LoopID: "loop-memory", Iteration: 2, Module: "loader_windows", File: "build.sh",
		Old: "checksum = 0", New: "checksum = recomputed",
		Reason: "recompute OptionalHeader.CheckSum", Kind: EditKindModel,
	}); err != nil {
		t.Fatal(err)
	}
	current := cycleSummary{
		Execution:      executionVerified,
		Mechanism:      "static-hygiene",
		HighFindings:   0,
		StaticFindings: 2,
		Note:           "recompute OptionalHeader.CheckSum over the linked image with the field zeroed",
		Telemetry:      &TelemetryStats{Coverage: TelemetryCoverage{Delivered: []string{"etw", "kernel"}}},
	}
	e.recordTechniqueMemory(ctx, Cycle{LoopID: "loop-memory", Iteration: 2, Execution: executionVerified, Findings: 1, TraceID: 7}, current, gateExecuting)

	techniques, err := e.memorySearch(ctx, "pe/checksum", "", "", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(techniques) != 1 {
		t.Fatalf("techniques = %+v, want one", techniques)
	}
	technique := techniques[0]
	if technique.Wins != 1 || technique.Samples != 1 || technique.AvgScore != 4 {
		t.Fatalf("score aggregate = %+v, want one win at 4", technique)
	}
	if !strings.Contains(technique.Note, "CheckSum") {
		t.Fatalf("note = %q, want the implementation note", technique.Note)
	}
	if len(technique.Examples) != 1 || !strings.Contains(technique.Examples[0].New, "recomputed") {
		t.Fatalf("examples = %+v, want the source edit", technique.Examples)
	}

	result, err := e.loopMemoryTool().Call(ctx, json.RawMessage(`{"rule":"pe/checksum"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if text := result.Flatten(); !strings.Contains(text, "CheckSum") || !strings.Contains(text, "recomputed") {
		t.Fatalf("tool output = %s", text)
	}

	e.last = &Cycle{Summary: `{"execution":"verified"}`}
	if brief := e.loopMemoryBrief(); !strings.Contains(brief, "pe/checksum") {
		t.Fatalf("brief = %q, want the verified rule", brief)
	}
}

func TestLoopMemoryRecordsAfterProductionGateOrder(t *testing.T) {
	db, err := OpenTelemetryDB(filepath.Join(t.TempDir(), "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()

	previous := cycleSummary{
		Execution:      executionVerified,
		HighFindings:   1,
		StaticFindings: 2,
		TopFindings:    []string{"high pe/checksum PE checksum"},
		Telemetry:      &TelemetryStats{Coverage: TelemetryCoverage{Delivered: []string{"etw", "kernel"}}},
	}
	encoded, _ := json.Marshal(previous)
	e := &evolver{cfg: EvolveConfig{LoopID: "loop-memory"}, db: db, logf: func(logging.Class, string, ...any) {}}
	e.cycles = []Cycle{{ID: 1, LoopID: "loop-memory", Iteration: 1, Execution: executionVerified, Summary: string(encoded)}}
	e.lastComparable = &e.cycles[0]
	e.lastExecuting = &e.cycles[0]
	if err := db.SaveEdit(ctx, EditRecord{
		LoopID: "loop-memory", Iteration: 2, Module: "loader_windows", File: "build.sh",
		Old: "checksum = 0", New: "checksum = recomputed",
		Reason: "recompute OptionalHeader.CheckSum", Kind: EditKindModel,
	}); err != nil {
		t.Fatal(err)
	}
	current := cycleSummary{
		Execution:      executionVerified,
		Mechanism:      "static-hygiene",
		HighFindings:   0,
		StaticFindings: 2,
		Note:           "recompute OptionalHeader.CheckSum over the linked image with the field zeroed",
		Telemetry:      &TelemetryStats{Coverage: TelemetryCoverage{Delivered: []string{"etw", "kernel"}}},
	}
	currentJSON, _ := json.Marshal(current)
	cycle := Cycle{ID: 2, LoopID: "loop-memory", Iteration: 2, Execution: executionVerified, Findings: 1, TraceID: 7, Summary: string(currentJSON)}
	e.last = &cycle
	e.cycles = append(e.cycles, cycle)

	gate := e.recordExecution(&e.cycles[1], current)
	if gate != gateExecuting {
		t.Fatalf("gate = %v, want gateExecuting", gate)
	}
	e.recordTechniqueMemory(ctx, e.cycles[1], current, gate)

	techniques, err := e.memorySearch(ctx, "pe/checksum", "", "", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(techniques) != 1 {
		t.Fatalf("techniques = %+v, want one recorded technique after the production gate order", techniques)
	}
}

func TestLoopMemoryRecordsStaticHygieneBacklog(t *testing.T) {
	db, err := OpenTelemetryDB(filepath.Join(t.TempDir(), "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()

	previous := cycleSummary{
		Execution:      executionVerified,
		StaticFindings: 3,
		Hygiene: []hygieneFinding{
			{Rule: "pe/checksum", Indicator: "PE checksum", Severity: "medium"},
			{Rule: "pe/sections", Indicator: "Non-standard PE sections", Severity: "medium"},
			{Rule: "pe/entropy", Indicator: ".rdata", Severity: "high"},
		},
		TopFindings: []string{"medium Elevated unbacked execute at Base: 000001dd60300000, Protection: 00000020, Size: 000000000039c000"},
		Telemetry:   &TelemetryStats{Coverage: TelemetryCoverage{Delivered: []string{"etw", "etwti"}}},
	}
	encoded, _ := json.Marshal(previous)
	e := &evolver{cfg: EvolveConfig{LoopID: "loop-memory"}, db: db, logf: func(logging.Class, string, ...any) {}}
	e.cycles = []Cycle{{ID: 1, LoopID: "loop-memory", Iteration: 1, Execution: executionVerified, Summary: string(encoded)}}
	e.lastComparable = &e.cycles[0]
	e.lastExecuting = &e.cycles[0]
	if err := db.SaveEdit(ctx, EditRecord{
		LoopID: "loop-memory", Iteration: 2, Module: "loader_windows", File: "build.sh",
		Old: "checksum = 0", New: "checksum = fixed", Reason: "post-link PE hygiene", Kind: EditKindModel,
	}); err != nil {
		t.Fatal(err)
	}
	current := cycleSummary{
		Execution:      executionVerified,
		Mechanism:      "static-hygiene",
		StaticFindings: 1,
		Hygiene: []hygieneFinding{
			{Rule: "pe/entropy", Indicator: ".rdata", Severity: "high"},
		},
		TopFindings: []string{"medium Elevated unbacked execute at Base: 0000025d6ba60000, Protection: 00000020, Size: 000000000039c000"},
		Telemetry:   &TelemetryStats{Coverage: TelemetryCoverage{Delivered: []string{"etw", "etwti"}}},
	}
	e.lastComparison = &e.cycles[0]
	e.recordTechniqueMemory(ctx, Cycle{LoopID: "loop-memory", Iteration: 2, Execution: executionVerified, Findings: 1, TraceID: 8}, current, gateExecuting)

	for _, rule := range []string{"pe/checksum", "pe/sections"} {
		techniques, err := e.memorySearch(ctx, rule, "", "", 5)
		if err != nil {
			t.Fatal(err)
		}
		if len(techniques) != 1 {
			t.Fatalf("%s: techniques = %+v, want the static-hygiene technique", rule, techniques)
		}
	}
	var volatile int
	if err := db.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM loop_memory_findings WHERE indicator LIKE '%Elevated unbacked execute%'`).Scan(&volatile); err != nil {
		t.Fatal(err)
	}
	if volatile != 0 {
		t.Fatalf("volatile dynamic finding was recorded %d time(s)", volatile)
	}
}
