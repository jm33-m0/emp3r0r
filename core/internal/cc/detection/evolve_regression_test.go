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

func TestInstrumentationDelta(t *testing.T) {
	baseline := &cycleSummary{Telemetry: &TelemetryStats{Coverage: TelemetryCoverage{
		Delivered: []string{"antimalware", "defender_trace", "etw", "etwti"},
	}}}
	changed := &cycleSummary{Telemetry: &TelemetryStats{Coverage: TelemetryCoverage{
		Delivered: []string{"antimalware", "defender_trace", "etw", "etwti", "hook", "kernel"},
	}}}
	got, note := instrumentationDelta(baseline, changed)
	if !got || !strings.Contains(note, "hook") || !strings.Contains(note, "kernel") {
		t.Fatalf("instrumentationDelta = %v %q, want hook/kernel change", got, note)
	}
	if got, _ := instrumentationDelta(baseline, baseline); got {
		t.Fatal("identical instrumentation was reported as changed")
	}
}

func TestNewHighFindings(t *testing.T) {
	baseline := []string{"high  .rdata", "medium analyzer/dynamic/hsb"}
	current := []string{"high  .rdata", "high  (`^dump0", "medium analyzer/dynamic/hsb"}
	got := newHighFindings(baseline, current)
	if len(got) != 1 || got[0] != "(`^dump0" {
		t.Fatalf("newHighFindings = %v, want [(`^dump0]", got)
	}
	if got := newHighFindings(baseline, baseline); len(got) != 0 {
		t.Fatalf("unchanged highs = %v", got)
	}
}

func TestFailureLayer(t *testing.T) {
	cases := []struct {
		name     string
		summary  cycleSummary
		expected string
	}{
		{"verified", cycleSummary{Execution: executionVerified}, ""},
		{"instrumentation", cycleSummary{Execution: executionOffline, InstrumentationChanged: true}, "instrumentation"},
		{"loader", cycleSummary{Execution: executionOffline, Telemetry: &TelemetryStats{ByCategory: map[string]int{}}}, "loader-start"},
		{"mapping", cycleSummary{Execution: executionOffline, Telemetry: &TelemetryStats{ByCategory: map[string]int{"process": 1}}}, "payload-mapping"},
		{"network", cycleSummary{Execution: executionOffline, Telemetry: &TelemetryStats{ByCategory: map[string]int{"process": 1, "memory": 4}}}, "agent-network"},
	}
	for _, tc := range cases {
		if got := failureLayer(&tc.summary); got != tc.expected {
			t.Errorf("%s: failureLayer = %q, want %q", tc.name, got, tc.expected)
		}
	}
}

func TestMechanismCatalogIsGeneral(t *testing.T) {
	brief := mechanismCatalogBrief()
	for _, mechanism := range []string{"self-load", "section-map", "producer", "producer-swap", "static-hygiene"} {
		if !strings.Contains(brief, mechanism) {
			t.Errorf("mechanism catalog is missing %s", mechanism)
		}
	}
	e := &evolver{}
	if got := e.mechanismBrief("producer"); !strings.Contains(got, "Selected mechanism: producer") {
		t.Fatalf("mechanismBrief = %q", got)
	}
}

func TestMechanismCatalogFiltersByPlatform(t *testing.T) {
	linux := mechanismCatalogBriefFor(platformLinux)
	for _, want := range []string{"stager", "agent", "producer", "build-flags", "static-hygiene"} {
		if !strings.Contains(linux, want) {
			t.Errorf("Linux mechanism catalog missing %s: %s", want, linux)
		}
	}
	for _, unwanted := range []string{"self-load", "module-stomp", "remote-apc"} {
		if strings.Contains(linux, unwanted) {
			t.Errorf("Linux mechanism catalog contains Windows mechanism %s", unwanted)
		}
	}
	windows := mechanismCatalogBriefFor(platformWindows)
	if strings.Contains(windows, "stager") || !strings.Contains(windows, "self-load") {
		t.Errorf("Windows mechanism catalog = %s", windows)
	}
}

func TestKnowledgeQueryUsesLastFindings(t *testing.T) {
	e := &evolver{last: &Cycle{Summary: `{"top_findings":["high  .rdata","medium analyzer/dynamic/hsb","medium  callstack private memory"],"mechanism":"section-map"}`}}
	got := e.knowledgeQuery("")
	if !strings.Contains(got, ".rdata") || !strings.Contains(got, "section-map") {
		t.Fatalf("knowledgeQuery = %q", got)
	}
	if strings.Contains(got, "analyzer/") {
		t.Fatalf("knowledgeQuery kept an analyzer rule: %q", got)
	}
}

func TestMethodologySearch(t *testing.T) {
	cases := map[string]string{
		"offline baseline execution":         "methodology/offline-after-baseline",
		"rededr hook instrumentation":        "methodology/instrumentation-changed",
		"rdata entropy packed":               "methodology/packed-payload-entropy",
		"agent dll producer":                 "methodology/producer-agent-compatibility",
		"rededr loadlibrary deadlock":        "methodology/sandbox-rededr-hook-deadlock",
		"module stomp":                       "methodology/mechanism-module-stomp",
		"glibc dynload compatibility":        "methodology/linux-glibc-dynload",
		"host.containers.internal podman c2": "methodology/container-host-dns",
	}
	for query, want := range cases {
		hits := methodologySearch(query, 5)
		found := false
		for _, hit := range hits {
			if hit.DocRef == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("methodologySearch(%q) did not return %s: %+v", query, want, hits)
		}
	}
}

func TestMethodologyReadAndSearchWithoutCache(t *testing.T) {
	e := &evolver{}
	result, err := e.knowledgeSearchTool().Call(context.Background(), []byte(`{"query":"offline baseline"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || !strings.Contains(result.Flatten(), "methodology/offline-after-baseline") {
		t.Fatalf("KnowledgeSearch without an external cache = %s", result.Flatten())
	}
	result, err = e.knowledgeReadTool().Call(context.Background(), []byte(`{"document_ref":"methodology/offline-after-baseline"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || !strings.Contains(result.Flatten(), "loader-start") {
		t.Fatalf("KnowledgeRead methodology = %s", result.Flatten())
	}
}

func TestFinalPayloadVerifiedTreatsLiveCheckInAsHealthy(t *testing.T) {
	cases := []struct {
		output      string
		err         error
		payloadSeen bool
		want        bool
	}{
		{"whoami output", nil, false, true},
		{"", nil, true, true},
		{"", errors.New("verification BOF killed by the sandbox"), true, true},
		{"", errors.New("agent did not come online"), false, false},
		{"", nil, false, false},
	}
	for _, tc := range cases {
		if got := finalPayloadVerified(tc.output, tc.err, tc.payloadSeen); got != tc.want {
			t.Errorf("finalPayloadVerified(%q, %v, %v) = %v, want %v", tc.output, tc.err, tc.payloadSeen, got, tc.want)
		}
	}
}

func TestRecordExecutionHoldsChangedInstrumentation(t *testing.T) {
	good := &Cycle{
		ID: 1, PayloadKey: "sha256:good", Findings: 10,
		Summary: `{"execution":"verified","high_findings":1,"telemetry":{"coverage":{"delivered":["etw"]}}}`,
	}
	e := &evolver{lastExecuting: good, lastComparable: good}
	next := &Cycle{ID: 2, PayloadKey: "sha256:weak", Findings: 10}
	gate := e.recordExecution(next, cycleSummary{
		Execution:              executionVerified,
		InstrumentationChanged: true,
		HighFindings:           5,
		StaticFindings:         31,
		Telemetry:              &TelemetryStats{Coverage: TelemetryCoverage{Delivered: []string{"etw", "etwti"}}},
	})
	if gate != gateUnchanged {
		t.Fatalf("gate = %v, want gateUnchanged for the first observation of a new instrumentation set", gate)
	}
	if e.lastExecuting != next {
		t.Fatalf("held cycle is not the restore target: %+v", e.lastExecuting)
	}
	if e.lastComparable != good {
		t.Fatalf("held cycle replaced the comparable baseline: %+v", e.lastComparable)
	}
}

func TestRegressionGateUsesSameInstrumentationEra(t *testing.T) {
	e := &evolver{logf: func(logging.Class, string, ...any) {}}
	e.cycles = []Cycle{
		{ID: 1, Summary: `{"execution":"verified","high_findings":1,"telemetry":{"coverage":{"delivered":["etw"]}}}`},
		{ID: 2, Summary: `{"execution":"verified","high_findings":1,"telemetry":{"coverage":{"delivered":["etw","etwti"]}}}`},
	}
	e.lastExecuting = &e.cycles[1]
	e.lastComparable = &e.cycles[1]

	prev := e.previousInstrumentationSummary()
	if prev == nil || len(prev.Telemetry.Coverage.Delivered) != 2 {
		t.Fatalf("instrumentation reference = %+v, want the newest verified cycle", prev)
	}
	stable := &cycleSummary{Telemetry: &TelemetryStats{Coverage: TelemetryCoverage{Delivered: []string{"etw", "etwti"}}}}
	if changed, note := instrumentationDelta(prev, stable); changed {
		t.Fatalf("stable instrumentation reported a change: %q", note)
	}

	next := &Cycle{ID: 3, Summary: `{"execution":"verified","high_findings":2,"telemetry":{"coverage":{"delivered":["etw","etwti"]}}}`}
	gate := e.recordExecution(next, cycleSummary{
		Execution:    executionVerified,
		HighFindings: 2,
		Telemetry:    &TelemetryStats{Coverage: TelemetryCoverage{Delivered: []string{"etw", "etwti"}}},
	})
	if gate != gateRegressed {
		t.Fatalf("gate = %v, want gateRegressed inside the new instrumentation era", gate)
	}
}

func TestConfirmOnlineDoesNotVouchForPayload(t *testing.T) {
	e := &evolver{
		cfg:               EvolveConfig{Verify: &stubVerifyOps{}},
		expectedAgentUUID: "current-payload",
	}
	c := &coordinator{e: e}
	if !c.confirmOnline(context.Background()) {
		t.Fatal("confirmOnline did not see the online agent")
	}
	if !e.agentSeenOnline.Load() {
		t.Fatal("loop-wide online latch was not recorded")
	}
	if e.payloadSeenOnline.Load() {
		t.Fatal("debugger online check vouched for the monitored payload")
	}
}

func TestDynamicRegionSummaryAttributesOuterAndProducer(t *testing.T) {
	dir := t.TempDir()
	shellcode := filepath.Join(dir, "pico.bin")
	if err := os.WriteFile(shellcode, make([]byte, 1000), 0o600); err != nil {
		t.Fatal(err)
	}
	feedback := Feedback{Findings: []Finding{
		{Severity: "medium", Tool: "hsb", Indicator: "Elevated unbacked execute at Base: 0x1000, Protection: 0x20, Size: 0x400"},
		{Severity: "medium", Tool: "hsb", Indicator: "Elevated unbacked execute at Base: 0x9000, Protection: 0x20, Size: 0x8000"},
		{Severity: "high", Tool: "pe-info", Indicator: "Base: 0x2000, Size: 0x8000"},
	}}
	regions := dynamicRegionSummary(feedback, shellcode)
	if len(regions) != 2 {
		t.Fatalf("regions = %v, want 2", regions)
	}
	if !strings.Contains(regions[0], "loader outer PICO") {
		t.Fatalf("outer region not attributed: %v", regions)
	}
	if !strings.Contains(regions[1], "producer PICO") {
		t.Fatalf("producer region not attributed: %v", regions)
	}
}

func TestFindingRegressionPrefersMediumReduction(t *testing.T) {
	base := findingCounts{
		High: 1, Medium: 16, Static: 0, Total: 39,
		DetectionHigh: 1, DetectionMedium: 16, StableTotal: 39,
	}
	cases := []struct {
		name    string
		current findingCounts
		want    bool
	}{
		{"medium reduction with more low findings", findingCounts{High: 1, Medium: 15, Static: 0, Total: 60, DetectionHigh: 1, DetectionMedium: 15, StableTotal: 60}, false},
		{"medium increase", findingCounts{High: 1, Medium: 17, Static: 0, Total: 39, DetectionHigh: 1, DetectionMedium: 17, StableTotal: 39}, true},
		{"equal medium and more total", findingCounts{High: 1, Medium: 16, Static: 0, Total: 40, DetectionHigh: 1, DetectionMedium: 16, StableTotal: 40}, true},
		{"equal medium and equal total", findingCounts{High: 1, Medium: 16, Static: 0, Total: 39, DetectionHigh: 1, DetectionMedium: 16, StableTotal: 39}, false},
		{"context medium increase is not progress", findingCounts{High: 1, Medium: 20, Static: 0, Total: 45, DetectionHigh: 1, DetectionMedium: 16, StableTotal: 39}, false},
		{"new static high signature", findingCounts{High: 2, Medium: 0, Static: 1, Total: 0, DetectionHigh: 1, HygieneHigh: 1, HygieneStatic: 1, StableTotal: 2}, true},
	}
	for _, tc := range cases {
		if got := findingRegression(base, tc.current); got != tc.want {
			t.Errorf("%s: findingRegression = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestVerdictChangeDecidesRegression(t *testing.T) {
	// The real loop-20261122-124851 shape: cycle 20 carried one Defender
	// verdict (also counted as a detection high) with fewer mediums; cycle 21
	// removed the verdict and gained six detection mediums.
	withVerdict := findingCounts{
		High: 1, Medium: 9, Static: 0, Total: 12,
		DetectionHigh: 1, DetectionMedium: 6, HygieneMedium: 3, StableTotal: 11,
		Verdicts: 1,
	}
	withoutVerdict := findingCounts{
		High: 0, Medium: 16, Static: 0, Total: 18,
		DetectionHigh: 0, DetectionMedium: 12, HygieneMedium: 3, StableTotal: 16,
	}
	if findingRegression(withVerdict, withoutVerdict) {
		t.Fatal("removing a verdict was treated as a regression because the medium count rose")
	}
	if !findingsImproved(withVerdict, withoutVerdict) {
		t.Fatal("removing a verdict was not counted as progress")
	}
	if !findingRegression(withoutVerdict, withVerdict) {
		t.Fatal("gaining a verdict was not a regression")
	}
	// A new detection high still wins over a removed verdict.
	newHigh := withoutVerdict
	newHigh.High = 2
	newHigh.DetectionHigh = 2
	if !findingRegression(withVerdict, newHigh) {
		t.Fatal("a new detection high was accepted because the verdict count fell")
	}
}

func TestVerdictFreeCycleReplacesFindingBaseline(t *testing.T) {
	baseline := Cycle{
		ID: 20, LoopID: "loop", Iteration: 20, PayloadKey: "sha256:verdict", Findings: 12, Verdicts: 1,
		Execution: executionVerified,
		Summary: `{"execution":"verified","high_findings":1,"medium_findings":9,"static_findings":0,` +
			`"detection_classified":true,"detection_high":1,"detection_medium":6,"hygiene_medium":3,` +
			`"stable_total":11,"verdicts":["Defender: HIT (Cache CacheLookup)"]}`,
	}
	current := Cycle{
		ID: 21, LoopID: "loop", Iteration: 21, PayloadKey: "sha256:clean", Findings: 18, Verdicts: 0,
		Execution: executionVerified,
		Summary: `{"execution":"verified","high_findings":0,"medium_findings":16,"static_findings":0,` +
			`"detection_classified":true,"detection_high":0,"detection_medium":12,"hygiene_medium":3,` +
			`"stable_total":16,"coverage_missing":["dynamic/pe_sieve: failed"]}`,
	}
	e := &evolver{logf: func(logging.Class, string, ...any) {}}
	e.cycles = []Cycle{baseline, current}
	e.lastExecuting = &e.cycles[0]
	e.lastComparable = &e.cycles[0]

	gate := e.recordExecution(&e.cycles[1], cycleSummary{
		Execution: executionVerified, HighFindings: 0, MediumFindings: 16, StaticFindings: 0,
		DetectionHigh: 0, DetectionMedium: 12, HygieneMedium: 3, StableTotal: 16,
		CoverageMissing: []string{"dynamic/pe_sieve: failed"},
	})
	if gate != gateUnchanged {
		t.Fatalf("gate = %v, want gateUnchanged for a verdict-free coverage gap", gate)
	}
	if e.lastExecuting == nil || e.lastExecuting.ID != 21 {
		t.Fatalf("verdict-free payload did not become the executing baseline: %+v", e.lastExecuting)
	}
	if e.lastComparable == nil || e.lastComparable.ID != 20 {
		t.Fatalf("incomplete-coverage cycle replaced the comparable baseline: %+v", e.lastComparable)
	}
}

func TestStaticWinCountsAsProgress(t *testing.T) {
	previous := findingCounts{
		DetectionHigh: 2, DetectionMedium: 13, HygieneMedium: 8, Static: 24, StableTotal: 44,
	}
	current := findingCounts{
		DetectionHigh: 2, DetectionMedium: 16, HygieneMedium: 6, Static: 7, StableTotal: 30,
	}
	if findingRegression(previous, current) {
		t.Fatal("a 17-finding static win was treated as a regression")
	}
	if !findingsImproved(previous, current) {
		t.Fatal("a 17-finding static win was not counted as progress")
	}
	if !findingRegression(
		findingCounts{DetectionHigh: 1, Static: 100, StableTotal: 200},
		findingCounts{DetectionHigh: 2, Static: 0, StableTotal: 2},
	) {
		t.Fatal("a new detection high was accepted despite the static win")
	}
}

func TestEarlyTerminationSkipsInstrumentationGate(t *testing.T) {
	cases := []struct {
		name  string
		stats *TelemetryStats
		want  bool
	}{
		{"missing analyzer", &TelemetryStats{Coverage: TelemetryCoverage{Missing: []string{"dynamic/analysis_metadata: early termination"}}}, true},
		{"analyzer status", &TelemetryStats{Coverage: TelemetryCoverage{Analyzers: map[string]string{"dynamic/analysis_metadata": "early termination"}}}, true},
		{"not started", &TelemetryStats{Coverage: TelemetryCoverage{Analyzers: map[string]string{"dynamic/analysis_metadata": "not started"}}}, true},
		{"normal", &TelemetryStats{Coverage: TelemetryCoverage{Analyzers: map[string]string{"dynamic/analysis_metadata": "ok"}}}, false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		if got := earlyTermination(tc.stats); got != tc.want {
			t.Errorf("%s: earlyTermination = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestChangedInstrumentationHeldThenConfirmed(t *testing.T) {
	good := &Cycle{ID: 1, Findings: 10, Summary: `{"execution":"verified","high_findings":1,"static_findings":29,"telemetry":{"coverage":{"delivered":["etw","etwti"]}}}`}
	e := &evolver{lastExecuting: good, lastComparable: good}
	first := &Cycle{ID: 2, Findings: 10, Summary: `{"execution":"verified","high_findings":1,"static_findings":31,"telemetry":{"coverage":{"delivered":["etw"]}}}`}
	gate := e.recordExecution(first, cycleSummary{
		Execution:              executionVerified,
		InstrumentationChanged: true,
		HighFindings:           1,
		StaticFindings:         31,
		Telemetry:              &TelemetryStats{Coverage: TelemetryCoverage{Delivered: []string{"etw"}}},
	})
	if gate != gateUnchanged || e.lastComparable != good {
		t.Fatalf("first observation of a new set was adopted: gate=%v baseline=%+v", gate, e.lastComparable)
	}

	e.cycles = []Cycle{*good, *first}
	prev := e.previousInstrumentationSummary()
	if prev == nil || len(prev.Telemetry.Coverage.Delivered) != 1 {
		t.Fatalf("instrumentation reference = %+v, want the last usable cycle", prev)
	}
	stable := &cycleSummary{Telemetry: &TelemetryStats{Coverage: TelemetryCoverage{Delivered: []string{"etw"}}}}
	if changed, note := instrumentationDelta(prev, stable); changed {
		t.Fatalf("a repeated set was reported as a change: %q", note)
	}

	confirmed := &Cycle{ID: 3, Findings: 10, Summary: `{"execution":"verified","high_findings":1,"static_findings":31,"telemetry":{"coverage":{"delivered":["etw"]}}}`}
	gate = e.recordExecution(confirmed, cycleSummary{
		Execution:      executionVerified,
		HighFindings:   1,
		StaticFindings: 31,
		Telemetry:      &TelemetryStats{Coverage: TelemetryCoverage{Delivered: []string{"etw"}}},
	})
	if gate != gateExecuting {
		t.Fatalf("gate = %v, want gateExecuting once the set repeated", gate)
	}
	if e.lastComparable != confirmed {
		t.Fatalf("confirmed set did not become the baseline: %+v", e.lastComparable)
	}
}

func TestHeldCycleIsRegressionBaselineWhenSetRepeats(t *testing.T) {
	e := &evolver{logf: func(logging.Class, string, ...any) {}}
	e.cycles = []Cycle{
		{ID: 1, Execution: executionVerified, Summary: `{"execution":"verified","high_findings":1,"static_findings":29,"telemetry":{"coverage":{"delivered":["etw","etwti"]}}}`},
		{ID: 2, Execution: executionVerified, Summary: `{"execution":"verified","high_findings":1,"static_findings":31,"telemetry":{"coverage":{"delivered":["etw"]}}}`},
	}
	e.lastExecuting = &e.cycles[1]
	e.lastComparable = &e.cycles[0]
	next := &Cycle{ID: 3, Execution: executionVerified, Summary: `{"execution":"verified","high_findings":2,"static_findings":31,"telemetry":{"coverage":{"delivered":["etw"]}}}`}
	gate := e.recordExecution(next, cycleSummary{
		Execution:      executionVerified,
		HighFindings:   2,
		StaticFindings: 31,
		Telemetry:      &TelemetryStats{Coverage: TelemetryCoverage{Delivered: []string{"etw"}}},
	})
	if gate != gateRegressed {
		t.Fatalf("gate = %v, want gateRegressed against the held cycle", gate)
	}
	if e.regressionBaseline == nil || e.regressionBaseline.ID != 2 {
		t.Fatalf("regression baseline = %+v, want the held cycle 2", e.regressionBaseline)
	}
}

func TestComparisonBaselineExcludesCurrentCycle(t *testing.T) {
	e := &evolver{logf: func(logging.Class, string, ...any) {}}
	e.cycles = []Cycle{
		{ID: 1, LoopID: "loop", Iteration: 1, Execution: executionVerified, Summary: `{"execution":"verified","high_findings":1,"telemetry":{"coverage":{"delivered":["etw"]}}}`},
		{ID: 2, LoopID: "loop", Iteration: 2, Execution: executionVerified, Summary: `{"execution":"verified","high_findings":2,"telemetry":{"coverage":{"delivered":["etw"]}}}`},
	}
	e.last = &e.cycles[1]
	gate := e.recordExecution(&e.cycles[1], cycleSummary{
		Execution:    executionVerified,
		HighFindings: 2,
		Telemetry:    &TelemetryStats{Coverage: TelemetryCoverage{Delivered: []string{"etw"}}},
	})
	if gate != gateRegressed {
		t.Fatalf("gate = %v, want gateRegressed against cycle 1, not a self-comparison", gate)
	}
	if e.lastComparison == nil || e.lastComparison.ID != 1 {
		t.Fatalf("comparison = %+v, want cycle 1", e.lastComparison)
	}
}
