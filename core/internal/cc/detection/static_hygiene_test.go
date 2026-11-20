package detection

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseInfoStaticHygiene(t *testing.T) {
	raw := json.RawMessage(`{
		"pe_info": {
			"checksum_info": {
				"is_valid": false,
				"needs_update": true,
				"stored_checksum": "0x0",
				"calculated_checksum": "0x92d8ef"
			},
			"detection_notes": [
				"Invalid PE checksum - Common in modified/packed files (~83% correlation with malware)",
				"Non-standard PE sections detected - May trigger static analysis",
				"Process injection capabilities detected"
			],
			"sections": [{"name": ".rdata", "entropy": 8.0}],
			"suspicious_imports": [{"function": "GetProcAddress", "dll": "kernel32.dll"}]
		}
	}`)
	findings := parseInfo(raw)
	want := map[string]string{
		"pe/checksum":  "medium",
		"pe/sections":  "medium",
		"pe/injection": "medium",
		"pe/entropy":   "high",
		"pe/import":    "medium",
	}
	got := map[string]Finding{}
	for _, finding := range findings {
		if finding.Stage != StageStatic {
			t.Fatalf("%s stage = %q, want static", finding.Rule, finding.Stage)
		}
		if finding.Tool != "pe-info" {
			t.Fatalf("%s tool = %q, want pe-info", finding.Rule, finding.Tool)
		}
		got[finding.Rule] = finding
	}
	for rule, severity := range want {
		finding, ok := got[rule]
		if !ok {
			t.Fatalf("missing %s finding: %+v", rule, findings)
		}
		if finding.Severity != severity {
			t.Fatalf("%s severity = %q, want %q", rule, finding.Severity, severity)
		}
	}
	if detail := got["pe/checksum"].Detail; !strings.Contains(detail, "0x0") || !strings.Contains(detail, "0x92d8ef") {
		t.Fatalf("checksum detail = %q", detail)
	}
	if got["pe/checksum"].SourceHint != "OUTPUT_ABS" {
		t.Fatalf("checksum source hint = %q", got["pe/checksum"].SourceHint)
	}
}

func TestParseInfoRejectsMalformedHygiene(t *testing.T) {
	raw := json.RawMessage(`{
		"pe_info": {
			"checksum_info": "not-an-object",
			"detection_notes": [123, null, {"x": 1}, "Invalid PE checksum"],
			"sections": [null, {"name": 42, "entropy": "8.0"}, {"name": ".rdata", "entropy": 8.0}],
			"suspicious_imports": [null, {"function": 42, "dll": null}]
		}
	}`)
	findings := parseInfo(raw)
	if len(findings) == 0 {
		t.Fatal("expected the valid note and section to survive")
	}
	for _, finding := range findings {
		if finding.Stage != StageStatic {
			t.Fatalf("%s stage = %q", finding.Rule, finding.Stage)
		}
		if finding.Indicator == "42" {
			t.Fatalf("numeric function was accepted as an import: %+v", finding)
		}
	}
}

func TestBuildFeedbackParsesPEAndDefenderRiskFactors(t *testing.T) {
	run := Run{
		ID: "risk-only",
		Risk: Risk{Factors: []string{
			"PE checksum mismatch observed",
			"Non-standard PE sections detected",
			"Process injection capabilities detected",
			"Dynamic: Critical: Microsoft Defender flagged the binary at runtime (5 threat verdicts)",
		}},
	}
	feedback := BuildFeedback(run)
	if feedback.Findings == nil {
		t.Fatal("no findings parsed from risk factors")
	}
	assertFindingRule(t, feedback.Findings, "pe/checksum", StageStatic, "medium")
	assertFindingRule(t, feedback.Findings, "pe/sections", StageStatic, "medium")
	assertFindingRule(t, feedback.Findings, "pe/injection", StageStatic, "medium")
	verdict := assertFindingRule(t, feedback.Findings, "defender/verdict", StageTelemetry, "critical")
	if !strings.Contains(verdict.Detail, "5 threat verdicts") {
		t.Fatalf("verdict detail = %q", verdict.Detail)
	}
	counts := countFindings(feedback.Findings)
	if counts.Static != 3 {
		t.Fatalf("static count = %d, want 3: %+v", counts.Static, feedback.Findings)
	}
}

func TestPEInfoChecksumMapsToBuildScript(t *testing.T) {
	dir := t.TempDir()
	build := "#!/bin/sh\ncp \"$BUILT\" \"$OUTPUT_ABS\"\n"
	if err := os.WriteFile(filepath.Join(dir, "build.sh"), []byte(build), 0o600); err != nil {
		t.Fatal(err)
	}
	run := Run{
		ID:   "checksum-source",
		Plan: Plan{ModuleDir: dir},
		Info: json.RawMessage(`{"pe_info":{"checksum_info":{"is_valid":false,"stored_checksum":"0x0","calculated_checksum":"0x92d8ef"}}}`),
	}
	feedback := BuildFeedback(run)
	finding := assertFindingRule(t, feedback.Findings, "pe/checksum", StageStatic, "medium")
	if len(finding.Sources) == 0 || finding.Sources[0].File != "build.sh" {
		t.Fatalf("checksum sources = %+v", finding.Sources)
	}
	for _, edit := range feedback.SourceEdits {
		if strings.Contains(edit.Action, "PE checksum") {
			return
		}
	}
	t.Fatalf("no checksum source edit in %+v", feedback.SourceEdits)
}

func TestParseStaticTagsStage(t *testing.T) {
	findings := parseStatic(json.RawMessage(`{"yara":{"matches":[{"rule":"TestRule","strings":[]}]}}`))
	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	if findings[0].Stage != StageStatic {
		t.Fatalf("stage = %q, want static", findings[0].Stage)
	}
}

func TestDefenderSummaryVerdicts(t *testing.T) {
	raw := json.RawMessage(`{
		"findings": {
			"defender_events": [
				{"event":"Behavior Monitoring BmDetection","event_id":42,"is_threat":true,"provider":"antimalware_engine","scan_target":"C:\\\\lab\\\\payload.exe","time":134395611386428221,"verdict":"HIT"},
				{"event":"Behavior Monitoring BmDetection","event_id":43,"is_threat":true,"provider":"antimalware_engine","time":134395611386428222,"verdict":"unsupported"},
				{"event":"Behavior Monitoring BmClean","event_id":44,"is_threat":false,"provider":"antimalware_engine","verdict":null}
			]
		}
	}`)
	parsed, err := parseTelemetry(raw, "rededr")
	if err != nil {
		t.Fatal(err)
	}
	verdicts := 0
	sawHit := false
	for _, event := range parsed.Events {
		if event.Category != "defender" || event.Signal != "verdict" {
			continue
		}
		verdicts++
		if event.Severity != "critical" {
			t.Fatalf("verdict severity = %q", event.Severity)
		}
		if strings.Contains(event.Event, "HIT") {
			sawHit = true
		}
	}
	if verdicts != 2 {
		t.Fatalf("verdict events = %d, want 2: %+v", verdicts, parsed.Events)
	}
	if !sawHit {
		t.Fatalf("HIT verdict missing: %+v", parsed.Events)
	}
}

func TestDefenderSummaryCapsEvents(t *testing.T) {
	events := make([]any, maxDefenderSummaryEvents*2)
	for i := range events {
		events[i] = map[string]any{
			"event":     fmt.Sprintf("Behavior Monitoring E%d", i),
			"is_threat": true,
			"verdict":   "HIT",
		}
	}
	raw, err := json.Marshal(map[string]any{"findings": map[string]any{"defender_events": events}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseTelemetry(raw, "rededr")
	if err != nil {
		t.Fatal(err)
	}
	verdicts := 0
	for _, event := range parsed.Events {
		if event.Category == "defender" && event.Signal == "verdict" {
			verdicts++
		}
	}
	if verdicts > maxDefenderSummaryEvents {
		t.Fatalf("verdict events = %d, cap is %d", verdicts, maxDefenderSummaryEvents)
	}
	if verdicts == 0 {
		t.Fatal("no verdict events survived the cap")
	}
}

func TestStaticFindingCounts(t *testing.T) {
	findings := []Finding{
		{Stage: StageStatic, Severity: "medium", Rule: "pe/checksum", Indicator: "PE checksum"},
		{Stage: StageStatic, Severity: "high", Rule: "yara", Indicator: "TestRule"},
		{Stage: StageTelemetry, Severity: "critical", Rule: "defender/verdict", Indicator: "Defender threat verdict"},
	}
	counts := countFindings(findings)
	if counts.Static != 2 || counts.High != 2 || counts.Medium != 1 || counts.Total != 3 {
		t.Fatalf("counts = %+v", counts)
	}
	if counts.DetectionHigh != 1 || counts.HygieneHigh != 1 || counts.HygieneMedium != 1 || counts.HygieneStatic != 2 || counts.StableTotal != 3 {
		t.Fatalf("split counts = %+v", counts)
	}
}

func TestCountFindingsSeparatesContext(t *testing.T) {
	findings := []Finding{
		{Stage: StageTelemetry, Tool: "telemetry", Severity: "critical", Rule: "defender/verdict", Indicator: "Defender threat verdict"},
		{Stage: StageStatic, Tool: "pe-info", Severity: "high", Rule: "pe/entropy", Indicator: ".rdata"},
		{Stage: StageStatic, Tool: "stringnalyzer", Severity: "medium", Indicator: ".rUJzD"},
		{Stage: StageTelemetry, Tool: "telemetry", Severity: "low", Rule: "telemetry/coverage", Indicator: "missing analyzer"},
	}
	counts := countFindings(findings)
	if counts.High != 2 || counts.Medium != 1 || counts.Static != 2 || counts.Total != 4 {
		t.Fatalf("raw counts = %+v", counts)
	}
	if counts.DetectionHigh != 1 || counts.HygieneHigh != 1 || counts.HygieneStatic != 1 || counts.StableTotal != 2 {
		t.Fatalf("split counts = %+v", counts)
	}
}

func TestSummarizeCycleTopFindingsExcludeContext(t *testing.T) {
	summary := summarizeCycle("loop", 1, Run{ID: "run"}, Feedback{Findings: []Finding{
		{Stage: StageStatic, Tool: "stringnalyzer", Severity: "medium", Indicator: ".rUJzD"},
		{Stage: StageStatic, Tool: "pe-info", Severity: "medium", Rule: "pe/checksum", Indicator: "PE checksum"},
	}}, "", "", "self-load", "agent.bin", "donut", executionVerified, nil, 0, false)
	if len(summary.TopFindings) != 1 || !strings.Contains(summary.TopFindings[0], "pe/checksum") {
		t.Fatalf("top findings = %+v, want only the stable hygiene finding", summary.TopFindings)
	}
	if len(summary.Hygiene) != 1 || summary.Hygiene[0].Rule != "pe/checksum" {
		t.Fatalf("hygiene = %+v", summary.Hygiene)
	}
}

func TestReportDoesNotClaimNoStaticWhenStaticExists(t *testing.T) {
	summary, err := json.Marshal(cycleSummary{
		Execution:      executionVerified,
		MediumFindings: 1,
		StaticFindings: 1,
		TopFindings:    []string{"medium pe/checksum PE checksum"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cycles := []Cycle{{
		Iteration:  1,
		PayloadKey: "sha256:static",
		Execution:  executionVerified,
		Summary:    string(summary),
	}}
	report := RenderLoopReport(map[string]any{"loop_id": "loop-static"}, cycles, nil)
	if strings.Contains(report, "No static YARA/CheckPlz/Stringnalyzer signature finding was recorded") {
		t.Fatalf("report claimed no static finding while static count is non-zero:\n%s", report)
	}
}

func TestHygieneSummaryKeepsStableStaticFindings(t *testing.T) {
	findings := []Finding{
		{
			Stage: StageStatic, Tool: "pe-info", Severity: "medium", Rule: "pe/checksum",
			Indicator: "PE checksum", Detail: "stored checksum 0x0, calculated 0x92d8ef",
			Sources: []SourceLocation{{File: "build.sh", Line: 12}},
		},
		{Stage: StageStatic, Tool: "pe-info", Severity: "high", Rule: "pe/entropy", Indicator: ".rdata"},
		{Stage: StageStatic, Tool: "stringnalyzer", Severity: "medium", Indicator: ".rUJzD"},
		{Stage: StageTelemetry, Tool: "defender", Severity: "critical", Rule: "defender/verdict", Indicator: "Defender threat verdict"},
	}
	items := hygieneSummary(findings)
	if len(items) != 2 {
		t.Fatalf("hygiene items = %+v, want checksum and entropy", items)
	}
	if items[0].Rule != "pe/checksum" || items[0].Source != "build.sh:12" {
		t.Fatalf("checksum item = %+v", items[0])
	}
	if items[1].Rule != "pe/entropy" || items[1].Indicator != ".rdata" {
		t.Fatalf("entropy item = %+v", items[1])
	}
	for _, item := range items {
		if item.Indicator == ".rUJzD" {
			t.Fatalf("stringnalyzer indicator entered the stable backlog: %+v", items)
		}
	}
	if line := formatHygiene(items[0]); !strings.Contains(line, "pe/checksum") || !strings.Contains(line, "build.sh:12") {
		t.Fatalf("formatted hygiene = %q", line)
	}
}

func TestHygieneBacklogPrefersLastExecutingPayload(t *testing.T) {
	good, _ := json.Marshal(cycleSummary{Hygiene: []hygieneFinding{{Rule: "pe/checksum", Indicator: "PE checksum"}}})
	bad, _ := json.Marshal(cycleSummary{Hygiene: []hygieneFinding{{Rule: "pe/entropy", Indicator: ".zdata"}}})
	e := &evolver{
		last:          &Cycle{Summary: string(bad)},
		lastExecuting: &Cycle{Summary: string(good)},
	}
	lines := e.hygieneLines()
	if len(lines) != 1 || !strings.Contains(lines[0], "pe/checksum") {
		t.Fatalf("hygiene backlog = %+v, want the last executing payload", lines)
	}
}

func TestRenderLoopReportShowsHygieneBacklog(t *testing.T) {
	first, _ := json.Marshal(cycleSummary{
		Execution:      executionVerified,
		StaticFindings: 2,
		Hygiene: []hygieneFinding{
			{Rule: "pe/checksum", Indicator: "PE checksum", Severity: "medium", Source: "build.sh:12"},
			{Rule: "pe/entropy", Indicator: ".rdata", Severity: "high"},
		},
	})
	final, _ := json.Marshal(cycleSummary{
		Execution:      executionVerified,
		StaticFindings: 1,
		Hygiene:        []hygieneFinding{{Rule: "pe/entropy", Indicator: ".rdata", Severity: "high"}},
	})
	cycles := []Cycle{
		{Iteration: 1, PayloadKey: "sha256:first", Execution: executionVerified, Summary: string(first)},
		{Iteration: 2, PayloadKey: "sha256:final", Execution: executionVerified, Summary: string(final)},
	}
	report := RenderLoopReport(map[string]any{"loop_id": "loop-hygiene"}, cycles, nil)
	for _, want := range []string{
		"## Static hygiene",
		"`pe/checksum PE checksum`",
		"not in final payload",
		"`pe/entropy .rdata`",
		"present",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
	summary := RenderLoopSummary(map[string]any{"loop_id": "loop-hygiene"}, cycles, nil)
	if !strings.Contains(summary, "**Static hygiene:** 1 open") {
		t.Fatalf("summary missing hygiene count:\n%s", summary)
	}
}

func assertFindingRule(t *testing.T, findings []Finding, rule string, stage StageKind, severity string) Finding {
	t.Helper()
	for _, finding := range findings {
		if finding.Rule != rule {
			continue
		}
		if finding.Stage != stage {
			t.Fatalf("%s stage = %q, want %q", rule, finding.Stage, stage)
		}
		if finding.Severity != severity {
			t.Fatalf("%s severity = %q, want %q", rule, finding.Severity, severity)
		}
		return finding
	}
	t.Fatalf("missing %s finding: %+v", rule, findings)
	return Finding{}
}
