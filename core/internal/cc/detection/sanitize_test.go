package detection

import (
	"context"
	"strings"
	"testing"
)

func TestTelemetrySanitizesTargetStrings(t *testing.T) {
	db := openTestTelemetry(t)
	fixture := `[
	 {"type":"process_query","func":"peb","pid":100,
	  "image_path":"C:\\Users\\x\\evil\u001b]0;pwn\u0007.exe"},
	 {"type":"etw","event":"Behavior Monitoring BmDetection",
	  "etw_provider_name":"Microsoft-Antimalware-Engine\u001b[31m","etw_pid":300,
	  "processid":100,"name":"Behavior:Win32/Test\u001b]0;pwn\u0007",
	  "imagepath":"C:\\Users\\x\\evil\u001b[31m.exe","trace_id":9,
	  "event_time":134382680160000000}]`
	trace, err := db.Import(context.Background(), []byte(fixture), ImportOptions{Path: "telemetry\x1b]0;pwn\x07.json"})
	if err != nil {
		t.Fatal(err)
	}
	for provider := range trace.Coverage.Providers {
		if strings.ContainsRune(provider, '\x1b') {
			t.Fatalf("coverage provider still contains ESC: %q", provider)
		}
	}
	findings, err := db.Findings(context.Background(), trace.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("no findings")
	}
	for _, finding := range findings {
		if strings.ContainsRune(finding.Indicator, '\x1b') || strings.ContainsRune(finding.Detail, '\x1b') {
			t.Fatalf("finding still contains ESC: %+v", finding)
		}
	}
	result, err := db.Query(context.Background(),
		`SELECT provider, event, path FROM events WHERE category = 'defender'`, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range result.Rows {
		for _, cell := range row {
			if text, ok := cell.(string); ok && strings.ContainsRune(text, '\x1b') {
				t.Fatalf("query cell still contains ESC: %q", text)
			}
		}
	}
	payloads, err := db.ListPayloads(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range payloads {
		if strings.ContainsRune(payload.Label, '\x1b') || strings.ContainsRune(payload.ArtifactPath, '\x1b') {
			t.Fatalf("payload output still contains ESC: %+v", payload)
		}
	}
	SanitizeTelemetryTrace(&trace)
	if trace.Meta != nil {
		t.Fatalf("trace meta was not dropped: %+v", trace.Meta)
	}
	if strings.ContainsRune(trace.PayloadImage, '\x1b') {
		t.Fatalf("trace payload image still contains ESC: %q", trace.PayloadImage)
	}
}

func TestSanitizeFeedbackStripsTargetText(t *testing.T) {
	feedback := Feedback{
		Notes:       []string{"note\x1b]0;pwn\x07"},
		RiskFactors: []string{"factor\x1b[31m"},
		Findings: []Finding{{
			Stage: StageTelemetry, Tool: "telemetry", Severity: "high",
			Rule: "telemetry/test", Indicator: "indicator\x1b]0;pwn\x07",
			Detail: "detail\x1b[31m", Sources: []SourceLocation{{File: "file\x1b[31m", Excerpt: "excerpt\x1b[31m"}},
		}},
		SourceEdits: []SourceEdit{{
			File: "file\x1b[31m", Excerpt: "excerpt\x1b[31m",
			Reason: "reason\x1b[31m", Action: "action\x1b[31m",
		}},
		Pending: []PendingStage{{
			Kind: StageDynamic, Tool: "tool\x1b[31m",
			Status: "status\x1b[31m", Reason: "reason\x1b[31m",
		}},
		Telemetry: &TelemetryRun{
			Source:       "rededr\x1b[31m",
			PayloadImage: "image\x1b[31m",
			Coverage: TelemetryCoverage{
				Delivered: []string{"etw\x1b[31m"},
				Providers: map[string]int{"provider\x1b[31m": 1},
			},
			Stats: &TelemetryStats{
				ByRule: map[string]int{"rule\x1b[31m": 1},
				Coverage: TelemetryCoverage{
					Missing:   []string{"hook\x1b[31m"},
					Providers: map[string]int{"stats\x1b[31m": 1},
				},
			},
		},
	}
	SanitizeFeedback(&feedback)
	text := strings.Join([]string{
		strings.Join(feedback.Notes, " "),
		strings.Join(feedback.RiskFactors, " "),
		feedback.Findings[0].Indicator, feedback.Findings[0].Detail,
		feedback.Findings[0].Sources[0].File, feedback.Findings[0].Sources[0].Excerpt,
		feedback.SourceEdits[0].Reason, feedback.SourceEdits[0].Action,
		feedback.Pending[0].Reason, feedback.Telemetry.Source,
		feedback.Telemetry.PayloadImage,
	}, " ")
	if strings.ContainsRune(text, '\x1b') {
		t.Fatalf("feedback still contains ESC: %q", text)
	}
	for provider := range feedback.Telemetry.Coverage.Providers {
		if strings.ContainsRune(provider, '\x1b') {
			t.Fatalf("provider still contains ESC: %q", provider)
		}
	}
	for rule := range feedback.Telemetry.Stats.ByRule {
		if strings.ContainsRune(rule, '\x1b') {
			t.Fatalf("rule still contains ESC: %q", rule)
		}
	}
}

func TestSanitizeRiskStripsTerminalEscapes(t *testing.T) {
	risk := Risk{Level: "high\x1b]0;pwn\x07", Factors: []string{"factor\x1b[31m"}}
	SanitizeRisk(&risk)
	if strings.ContainsRune(risk.Level, '\x1b') || strings.ContainsRune(strings.Join(risk.Factors, " "), '\x1b') {
		t.Fatalf("risk still contains ESC: %+v", risk)
	}
}
