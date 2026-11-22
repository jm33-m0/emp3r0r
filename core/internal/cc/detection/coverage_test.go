package detection

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCoverageGapDoesNotReplaceComparableBaseline(t *testing.T) {
	e := &evolver{}
	good := &Cycle{ID: 1, PayloadKey: "sha256:good", Findings: 10, Summary: `{"execution":"verified","high_findings":1}`}
	e.lastExecuting = good
	e.lastComparable = good

	gap := &Cycle{ID: 2, PayloadKey: "sha256:gap", Findings: 10}
	gate := e.recordExecution(gap, cycleSummary{
		Execution:       executionVerified,
		HighFindings:    0,
		CoverageMissing: []string{"dynamic/yara: failed"},
	})
	if gate != gateUnchanged {
		t.Fatalf("gate = %v, want gateUnchanged for a coverage gap", gate)
	}
	if e.lastExecuting != gap {
		t.Fatalf("lastExecuting = %+v, want the executing gap cycle", e.lastExecuting)
	}
	if e.lastComparable != good {
		t.Fatalf("lastComparable = %+v, want the complete baseline", e.lastComparable)
	}

	worse := &Cycle{ID: 3, PayloadKey: "sha256:worse", Findings: 10}
	gate = e.recordExecution(worse, cycleSummary{Execution: executionVerified, HighFindings: 2})
	if gate != gateRegressed {
		t.Fatalf("gate = %v, want regression against the last comparable baseline", gate)
	}
	if e.lastComparable != good {
		t.Fatalf("regression replaced the comparable baseline: %+v", e.lastComparable)
	}
}

func TestCoverageGapCountsAsNoMechanismProgress(t *testing.T) {
	summary := func(mechanism string, missing ...string) string {
		encoded, _ := json.Marshal(cycleSummary{Mechanism: mechanism, CoverageMissing: missing})
		return string(encoded)
	}
	c := &coordinator{e: &evolver{cycles: []Cycle{
		{LoopID: "loop", Iteration: 1, Summary: summary("build-flags", "dynamic/yara: failed")},
		{LoopID: "loop", Iteration: 2, Summary: summary("build-flags", "dynamic/yara: failed")},
	}}}
	if !c.repeatedNonImprovingMechanism("build-flags") {
		t.Fatal("a coverage-gapped mechanism sequence was treated as progress")
	}
}

func TestRenderLoopReportWarnsAboutCoverage(t *testing.T) {
	summary, _ := json.Marshal(cycleSummary{
		Execution:       executionVerified,
		HighFindings:    1,
		CoverageMissing: []string{"dynamic/yara: failed", "dynamic/pe_sieve: failed"},
	})
	cycles := []Cycle{{Iteration: 1, PayloadKey: "sha256:gap", Execution: executionVerified, Summary: string(summary)}}
	report := RenderLoopReport(map[string]any{"loop_id": "loop-coverage"}, cycles, nil)
	if !strings.Contains(report, "Final payload coverage is incomplete") || !strings.Contains(report, "dynamic/yara") {
		t.Fatalf("report does not warn about coverage:\n%s", report)
	}
	executive := RenderLoopSummary(map[string]any{"loop_id": "loop-coverage"}, cycles, nil)
	if !strings.Contains(executive, "| Coverage | incomplete") {
		t.Fatalf("summary does not warn about coverage:\n%s", executive)
	}
}

func TestReportMarksInstrumentationAndOverlayBlindSpots(t *testing.T) {
	reportCycle := func(iteration int, delivered []string, tops []string, note string, high, static int) Cycle {
		summary, err := json.Marshal(cycleSummary{
			Execution:      executionVerified,
			TopFindings:    tops,
			Note:           note,
			HighFindings:   high,
			StaticFindings: static,
			Telemetry:      &TelemetryStats{Coverage: TelemetryCoverage{Delivered: delivered}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return Cycle{LoopID: "loop", Iteration: iteration, Execution: executionVerified, Findings: len(tops), Summary: string(summary)}
	}
	cycles := []Cycle{
		reportCycle(1, []string{"etw", "etwti"}, []string{"high telemetry/thread-suspend SuspendThread", "high pe/entropy .rdata"}, "baseline", 2, 29),
		reportCycle(2, []string{"etw"}, []string{"high telemetry/process-access OpenProcess"}, "Container move: RC4 key+ciphertext appended as a PE overlay", 1, 31),
	}
	out := RenderLoopSummary(map[string]any{"loop_id": "loop"}, cycles, nil)
	for _, want := range []string{"Counts are not comparable", "removed `etwti`", "Not attributable", "analyzer blind spot"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q:\n%s", want, out)
		}
	}
}
