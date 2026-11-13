package detection

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/tool"
)

const redEdrFixture = `[
 {"type":"meta","func":"init","trace_id":41,"version":"1.0","do_etw":true,"do_etwti":false,
  "do_antimalwareengine":false,"targets":["malware"],"event_time":134382680038271379},
 {"type":"process_query","func":"peb","id":2,"pid":8216,"parent_pid":4856,
  "image_path":"C:\\Users\\Public\\Downloads\\sample.exe","working_dir":"C:\\Windows\\",
  "is_debugged":0,"is_protected_process":0,"trace_id":41,"event_time":134382680109164370},
 {"type":"etw","event":"ProcessStartStart ","etw_provider_name":"Microsoft-Windows-Kernel-Process",
  "etw_pid":8216,"etw_tid":4512,"processid":6476,"parentprocessid":8216,
  "imagename":"\\Device\\HarddiskVolume3\\Users\\rededr\\AppData\\Local\\Temp\\run\\sample.tmp",
  "trace_id":41,"event_time":134382680150000000},
 {"type":"etw","event":"CreateNewFileInfo ","etw_provider_name":"Microsoft-Windows-Kernel-File",
  "etw_pid":8216,"filename":"\\Device\\HarddiskVolume3\\Users\\rededr\\AppData\\Local\\Temp\\run\\drop.bin",
  "trace_id":41,"event_time":134382680160000000},
 {"type":"etw","event":"PspLogAuditOpenProcessEvent","etw_provider_name":"Microsoft-Windows-Kernel-Audit-API-Calls",
  "etw_event_id":5,"etw_pid":8216,"targetprocessid":4,"desiredaccess":2035711,
  "trace_id":41,"event_time":134382680170000000},
 {"type":"etw","event":"ThreatFound","etw_provider_name":"Microsoft-Antimalware-Engine",
  "etw_pid":1234,"threatname":"Trojan:Win32/Test","filename":"C:\\Users\\Public\\sample.exe",
  "trace_id":41,"event_time":134382680180000000}
]`

func openTestTelemetry(t *testing.T) *TelemetryDB {
	t.Helper()
	db, err := OpenTelemetryDB(filepath.Join(t.TempDir(), "telemetry.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func findingRules(findings []Finding) map[string]Finding {
	out := map[string]Finding{}
	for _, finding := range findings {
		out[finding.Rule] = finding
	}
	return out
}

func TestTelemetryImportsRedEdrAndFinds(t *testing.T) {
	db := openTestTelemetry(t)
	trace, err := db.Import(context.Background(), []byte(redEdrFixture), ImportOptions{
		RunID: "loader_windows-deadbeef00", Module: "loader_windows", ArtifactSHA256: "deadbeef",
	})
	if err != nil {
		t.Fatal(err)
	}
	if trace.Events != 5 || trace.Source != "rededr" {
		t.Fatalf("trace = %+v", trace)
	}
	if trace.Meta["payload_pid"] == nil || trace.Meta["payload_pid"].(int64) != 8216 {
		t.Fatalf("payload pid = %v", trace.Meta["payload_pid"])
	}
	findings, err := db.Findings(context.Background(), trace.ID)
	if err != nil {
		t.Fatal(err)
	}
	rules := findingRules(findings)
	if rules["telemetry/child-process"].Severity != "high" {
		t.Fatalf("child process finding = %+v", rules["telemetry/child-process"])
	}
	if rules["telemetry/file-write"].Severity != "medium" {
		t.Fatalf("file write finding = %+v", rules["telemetry/file-write"])
	}
	if rules["telemetry/process-access"].Severity != "high" {
		t.Fatalf("process access finding = %+v", rules["telemetry/process-access"])
	}
	if rules["defender/verdict"].Severity != "critical" {
		t.Fatalf("defender finding = %+v", rules["defender/verdict"])
	}
	if !strings.Contains(rules["telemetry/child-process"].Detail, "6476") {
		t.Fatalf("child detail = %q", rules["telemetry/child-process"].Detail)
	}

	result, err := db.Query(context.Background(),
		`SELECT event, count(*) AS n FROM events WHERE trace_pk = `+itoa(trace.ID)+` GROUP BY event ORDER BY n DESC`, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 5 || len(result.Columns) != 2 {
		t.Fatalf("query result = %+v", result)
	}

	// Re-importing the same run and trace replaces the trace and its events.
	again, err := db.Import(context.Background(), []byte(redEdrFixture), ImportOptions{
		RunID: "loader_windows-deadbeef00", Module: "loader_windows", ArtifactSHA256: "deadbeef",
	})
	if err != nil {
		t.Fatal(err)
	}
	var traces, events int
	if err := db.db.QueryRow(`SELECT count(*) FROM traces`).Scan(&traces); err != nil {
		t.Fatal(err)
	}
	if err := db.db.QueryRow(`SELECT count(*) FROM events WHERE trace_pk = ?`, again.ID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if traces != 1 || events != 5 {
		t.Fatalf("traces=%d events=%d", traces, events)
	}
}

func TestTelemetryRejectsWriteQueries(t *testing.T) {
	db := openTestTelemetry(t)
	for _, statement := range []string{
		"DELETE FROM events",
		"PRAGMA journal_mode=DELETE",
		"SELECT 1; DROP TABLE events",
		"SELECT 1 -- comment",
		"ATTACH DATABASE 'x' AS y",
		"INSERT INTO traces(source) VALUES('x')",
	} {
		if _, err := db.Query(context.Background(), statement, 10); err == nil {
			t.Fatalf("query %q was accepted", statement)
		}
	}
}

func TestTelemetryQueryLimit(t *testing.T) {
	db := openTestTelemetry(t)
	if _, err := db.Import(context.Background(), []byte(redEdrFixture), ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(context.Background(), `SELECT id FROM events ORDER BY id`, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 3 || !result.Truncated {
		t.Fatalf("result = %+v", result)
	}
}

func TestTelemetryImportsDefenderObserverJSONL(t *testing.T) {
	db := openTestTelemetry(t)
	payload := `{"timestamp":"2026-11-12T09:43:06.4430000Z","providerName":"Microsoft-Antimalware-Engine",` +
		`"id":19,"symbol":"BmEvent","task":"BehaviorMonitoring","processId":43940,` +
		`"processName":"sample.exe","threadId":4,"payload":{"Path":"C:\\Users\\Public\\sample.exe","ThreatName":""}}`
	trace, err := db.Import(context.Background(), []byte(payload+"\n"+payload), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if trace.Source != "defender_observer" || trace.Events != 2 {
		t.Fatalf("trace = %+v", trace)
	}
	result, err := db.Query(context.Background(), `SELECT category, pid, path FROM events ORDER BY id`, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 2 || result.Rows[0][0] != "defender" || result.Rows[0][1] != int64(43940) {
		t.Fatalf("rows = %+v", result.Rows)
	}
	if result.Rows[0][2] != `C:\Users\Public\sample.exe` {
		t.Fatalf("path = %v", result.Rows[0][2])
	}
}

func TestTelemetryImportsLitterBoxWrapper(t *testing.T) {
	db := openTestTelemetry(t)
	wrapped := `{"rededr":{"status":"completed","findings":{"events":[` +
		`{"type":"etw","event":"ImageLoadInfo","etw_provider_name":"Microsoft-Windows-Kernel-Process",` +
		`"etw_pid":9,"processid":9,"imagename":"\\Device\\HarddiskVolume3\\Users\\x\\a.exe",` +
		`"imagesize":123,"trace_id":7,"event_time":134382680083633302}]}}}`
	trace, err := db.Import(context.Background(), []byte(wrapped), ImportOptions{Source: "litterbox-rededr"})
	if err != nil {
		t.Fatal(err)
	}
	if trace.Source != "litterbox-rededr" || trace.Events != 1 {
		t.Fatalf("trace = %+v", trace)
	}
}

func TestBuildFeedbackIncludesTelemetryAndMapsSource(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bootstrap.c"),
		[]byte("CreateProcessW(path, cmd, 0, 0, 0, 0, 0, 0, &si, &pi);\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := Run{
		ID: "loader_windows-deadbeef00", Module: "loader_windows",
		Plan: Plan{ModuleDir: dir, Artifact: Artifact{SHA256: "deadbeef"}},
		Telemetry: &TelemetryRun{
			TraceID: 1, Source: "rededr", Events: 2,
			Findings: []Finding{{
				Stage: StageTelemetry, Tool: "telemetry", Severity: "high",
				Rule: "telemetry/child-process", Indicator: "CreateProcessW",
				Detail: "payload created process 6476 from a temp path",
			}},
		},
	}
	feedback := BuildFeedback(run)
	if len(feedback.Findings) != 1 || feedback.Telemetry == nil || feedback.Telemetry.TraceID != 1 {
		t.Fatalf("feedback = %+v", feedback)
	}
	if feedback.Findings[0].Stage != StageTelemetry || len(feedback.Findings[0].Sources) == 0 {
		t.Fatalf("finding = %+v", feedback.Findings[0])
	}
}

func itoa(value int64) string { return strconv.FormatInt(value, 10) }

func TestAnalystTelemetryToolIsReadOnly(t *testing.T) {
	db := openTestTelemetry(t)
	if _, err := db.Import(context.Background(), []byte(redEdrFixture), ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bootstrap.c"), []byte("void f(void) {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	analyst, err := NewAnalyst(AnalystConfig{
		Provider:   scriptedProvider{answer: `{"summary":"ok","edits":[]}`},
		WorkingDir: dir, Telemetry: db,
	})
	if err != nil {
		t.Fatal(err)
	}
	var telemetryTool tool.CoreTool
	for _, candidate := range analyst.tools {
		if candidate.Name() == "TelemetryQuery" {
			telemetryTool = candidate
		}
	}
	if telemetryTool == nil {
		t.Fatal("TelemetryQuery tool is missing")
	}
	if !telemetryTool.IsReadOnly(nil) {
		t.Fatal("TelemetryQuery is not read-only")
	}
	result, err := telemetryTool.Call(context.Background(),
		json.RawMessage(`{"sql":"SELECT count(*) AS n FROM events"}`), nil)
	if err != nil || result.IsError || !strings.Contains(result.Flatten(), `"rows":[[5]]`) {
		t.Fatalf("query = %q err=%v", result.Flatten(), err)
	}
	result, err = telemetryTool.Call(context.Background(),
		json.RawMessage(`{"sql":"DELETE FROM events"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatalf("write query succeeded: %q", result.Flatten())
	}
}

func TestTelemetryDistinguishesDefenderVerdictFromScan(t *testing.T) {
	db := openTestTelemetry(t)
	fixture := `[{"type":"meta","trace_id":5},
	 {"type":"etw","event":"Behavior Monitoring BmNotificationHandleStart","etw_provider_name":"Microsoft-Antimalware-Engine",
	  "etw_pid":300,"pid":100,"ismultiprocdetection":"unsupported","trace_id":5},
	 {"type":"etw","event":"Cache MOACLookup","etw_provider_name":"Microsoft-Antimalware-Engine",
	  "etw_pid":300,"pid":100,"verdict":"unsupported","trace_id":5},
	 {"type":"etw","event":"Behavior Monitoring BmDetection","etw_provider_name":"Microsoft-Antimalware-Engine",
	  "etw_pid":300,"pid":100,"name":"Behavior:Win32/Inject.A","imagepath":"C:\\Users\\x\\a.exe","trace_id":5}]`
	trace, err := db.Import(context.Background(), []byte(fixture), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	findings, err := db.Findings(context.Background(), trace.ID)
	if err != nil {
		t.Fatal(err)
	}
	verdicts := 0
	for _, finding := range findings {
		if finding.Rule == "defender/verdict" {
			verdicts++
			if finding.Indicator != "Behavior:Win32/Inject.A" {
				t.Fatalf("verdict indicator = %q", finding.Indicator)
			}
		}
	}
	if verdicts != 1 {
		t.Fatalf("verdict findings = %d (%+v)", verdicts, findings)
	}
}

func TestCompareRunsReportsResolvedAndAdded(t *testing.T) {
	store := NewStore(t.TempDir())
	previous := Run{
		ID: "loader_windows-aaaa", Module: "loader_windows",
		Plan:      Plan{Artifact: Artifact{SHA256: "aaaa"}},
		StartedAt: time.Now().Add(-time.Hour), FinishedAt: time.Now().Add(-time.Hour),
		Telemetry: &TelemetryRun{Findings: []Finding{
			{Rule: "defender/verdict", Indicator: "Behavior:Win32/Old"},
			{Rule: "telemetry/child-process", Indicator: "CreateProcessW"},
		}},
	}
	current := Run{
		ID: "loader_windows-bbbb", Module: "loader_windows",
		Plan:      Plan{Artifact: Artifact{SHA256: "bbbb"}},
		StartedAt: time.Now(), FinishedAt: time.Now(),
		Telemetry: &TelemetryRun{Findings: []Finding{
			{Rule: "telemetry/child-process", Indicator: "CreateProcessW"},
			{Rule: "telemetry/file-write", Indicator: "CreateFileW"},
		}},
	}
	if _, err := store.Save(previous); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(current); err != nil {
		t.Fatal(err)
	}
	loop := &Loop{Store: store}
	comparison, err := loop.Compare(current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if comparison == nil || len(comparison.Resolved) != 1 || len(comparison.Added) != 1 {
		t.Fatalf("comparison = %+v", comparison)
	}
	if comparison.Resolved[0].Indicator != "Behavior:Win32/Old" {
		t.Fatalf("resolved = %+v", comparison.Resolved)
	}
	if comparison.Added[0].Indicator != "CreateFileW" {
		t.Fatalf("added = %+v", comparison.Added)
	}
}

func TestFetchTelemetryRejectsNonHTTPScheme(t *testing.T) {
	if _, err := FetchTelemetry(context.Background(), "file:///etc/passwd"); err == nil {
		t.Fatal("file scheme accepted")
	}
}

func TestPayloadViewsAndDiff(t *testing.T) {
	db := openTestTelemetry(t)
	first := `[{"type":"meta","trace_id":1},
	 {"type":"etw","event":"ProcessStartStart ","etw_provider_name":"Microsoft-Windows-Kernel-Process",
	  "etw_pid":100,"processid":200,"imagename":"\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe","trace_id":1}]`
	second := `[{"type":"meta","trace_id":2},
	 {"type":"etw","event":"ProcessStartStart ","etw_provider_name":"Microsoft-Windows-Kernel-Process",
	  "etw_pid":100,"processid":200,"imagename":"\\Device\\HarddiskVolume3\\Windows\\System32\\dllhost.exe","trace_id":2},
	 {"type":"etw","event":"Behavior Monitoring BmDetection","etw_provider_name":"Microsoft-Antimalware-Engine",
	  "etw_pid":300,"pid":100,"name":"Behavior:Win32/Test.A","trace_id":2}]`
	a, err := db.Import(context.Background(), []byte(first), ImportOptions{
		RunID: "run-a", Module: "loader_windows", ArtifactSHA256: "aaaa", Path: "/tmp/a.exe",
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := db.Import(context.Background(), []byte(second), ImportOptions{
		RunID: "run-b", Module: "loader_windows", ArtifactSHA256: "bbbb", Path: "/tmp/b.exe",
		ParentKey: a.PayloadKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if a.PayloadID == 0 || b.PayloadID == 0 || a.PayloadKey == b.PayloadKey {
		t.Fatalf("payload identities: a=%+v b=%+v", a, b)
	}
	payloads, err := db.ListPayloads(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 2 || payloads[0].ParentID != a.PayloadID {
		t.Fatalf("payloads = %+v", payloads)
	}
	// The per-payload view is queryable and contains only that payload.
	result, err := db.Query(context.Background(),
		`SELECT count(*) FROM `+b.PayloadTable, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 || result.Rows[0][0] != int64(2) {
		t.Fatalf("payload view = %+v", result.Rows)
	}
	diff, err := db.ComparePayloads(context.Background(), a.PayloadKey, b.PayloadKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Added) == 0 || diff.AddedTotal == 0 || len(diff.Removed) == 0 || diff.RemovedTotal == 0 {
		t.Fatalf("diff = %+v", diff)
	}
	// Re-importing the same artifact appends to the existing payload.
	if _, err := db.Import(context.Background(), []byte(first), ImportOptions{
		RunID: "run-a", Module: "loader_windows", ArtifactSHA256: "aaaa", Path: "/tmp/a.exe",
	}); err != nil {
		t.Fatal(err)
	}
	again, err := db.ListPayloads(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 2 {
		t.Fatalf("re-import created a payload: %+v", again)
	}
}
