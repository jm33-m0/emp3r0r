package detection

import (
	"context"
	"errors"
	"strings"
	"testing"
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
		"offline baseline execution":  "methodology/offline-after-baseline",
		"rededr hook instrumentation": "methodology/instrumentation-changed",
		"rdata entropy packed":        "methodology/packed-payload-entropy",
		"agent dll producer":          "methodology/producer-agent-compatibility",
		"rededr loadlibrary deadlock": "methodology/sandbox-rededr-hook-deadlock",
		"module stomp":                "methodology/mechanism-module-stomp",
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

func TestRecordExecutionRejectsChangedInstrumentation(t *testing.T) {
	e := &evolver{lastExecuting: &Cycle{ID: 1, PayloadKey: "sha256:good", Findings: 10}}
	gate := e.recordExecution(&Cycle{ID: 2, PayloadKey: "sha256:weak", Findings: 10}, cycleSummary{
		Execution:              executionVerified,
		InstrumentationChanged: true,
		HighFindings:           0,
	})
	if gate != gateUnchanged || e.lastExecuting == nil || e.lastExecuting.ID != 1 {
		t.Fatalf("instrumentation-changed cycle was adopted: gate=%v last=%+v", gate, e.lastExecuting)
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
