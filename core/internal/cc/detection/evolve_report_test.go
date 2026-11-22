package detection

import (
	"strings"
	"testing"
)

func TestReportUsesLastVerifiedVerdictFreePayload(t *testing.T) {
	cycles := []Cycle{
		{
			Iteration: 1, PayloadKey: "sha256:baseline", Execution: executionVerified, Findings: 48, Verdicts: 0,
			Summary: `{"execution":"verified","high_findings":3,"medium_findings":23,"static_findings":28,` +
				`"detection_classified":true,"detection_high":2,"detection_medium":13,"hygiene_high":1,` +
				`"hygiene_medium":10,"stable_total":27}`,
		},
		{
			Iteration: 20, PayloadKey: "sha256:verdict", Execution: executionVerified, Findings: 12, Verdicts: 1,
			Summary: `{"execution":"verified","high_findings":1,"medium_findings":9,"static_findings":0,` +
				`"detection_classified":true,"detection_high":1,"detection_medium":6,"hygiene_medium":3,` +
				`"stable_total":11,"verdicts":["Defender: HIT (Cache CacheLookup)"]}`,
		},
		{
			Iteration: 30, PayloadKey: "sha256:clean", Execution: executionVerified, Findings: 18, Verdicts: 0,
			Summary: `{"execution":"verified","high_findings":0,"medium_findings":16,"static_findings":0,` +
				`"detection_classified":true,"detection_high":0,"detection_medium":12,"hygiene_medium":3,` +
				`"stable_total":16,"coverage_missing":["dynamic/pe_sieve: failed"]}`,
		},
	}
	answer := map[string]any{
		"loop_id":                "loop-verdict",
		"last_executing_payload": "sha256:verdict",
		"last_verified_payload":  "sha256:clean",
		// A mistaken model summary must not relabel the verdict-free payload.
		"verdicts_before": []any{"Defender: HIT (Cache CacheLookup)"},
		"verdicts_after":  []any{"Defender: HIT (Cache CacheLookup)"},
	}
	report := RenderLoopReport(answer, cycles, nil)
	for _, want := range []string{
		"Final payload: `clean`",
		"| Before | none |",
		"| After | none |",
		"| Defender verdicts | 0 | 0 | 0 |",
		"| High findings | 3 | 0 | -3 |",
		"Finding baseline: cycle 20 `verdict` (verdicts=1, high=1, medium=9, total=12)",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
	if strings.Contains(report, "Final payload: `verdict`") {
		t.Fatalf("report kept the verdict-positive baseline as the final payload:\n%s", report)
	}
	if strings.Contains(report, "rejected or restored") {
		t.Fatalf("report claimed the final payload was rejected or restored:\n%s", report)
	}
	executive := RenderLoopSummary(answer, cycles, nil)
	for _, want := range []string{
		"| High findings | 3 | 0 | -3 |",
		"| Defender verdicts | 0 | 0 | 0 |",
		"finding baseline is cycle 20 (`verdict`",
	} {
		if !strings.Contains(executive, want) {
			t.Fatalf("executive summary missing %q:\n%s", want, executive)
		}
	}
}

func TestReportFindingChangesSkipsVolatileFindings(t *testing.T) {
	cycles := []Cycle{
		{
			Iteration: 1, Execution: executionVerified,
			Summary: `{"execution":"verified","top_findings":["medium Elevated unbacked execute at Base: 0x1, Protection: 0x20, Size: 0x1","medium Callstack contains private memory regions","medium pe/checksum PE checksum"]}`,
		},
		{
			Iteration: 2, Execution: executionVerified,
			Summary: `{"execution":"verified","top_findings":[]}`,
		},
	}
	changes, _ := reportFindingChanges(cycles, 1, nil)
	if len(changes) != 1 {
		t.Fatalf("changes = %+v, want only the stable pe/checksum finding", changes)
	}
	if !strings.Contains(changes[0].Finding, "pe/checksum") {
		t.Fatalf("change = %+v, want pe/checksum", changes[0])
	}
}
