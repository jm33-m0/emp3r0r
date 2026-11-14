package detection

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
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
	second := strings.Replace(payload, "09:43:06.4430000Z", "09:43:06.4440000Z", 1)
	trace, err := db.Import(context.Background(), []byte(payload+"\n"+second), ImportOptions{})
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
	if _, err := FetchTelemetry(context.Background(), "file:///etc/passwd", "http://127.0.0.1:1337"); err == nil {
		t.Fatal("file scheme accepted")
	}
}

func TestFetchTelemetryRejectsForeignOrigin(t *testing.T) {
	if _, err := FetchTelemetry(context.Background(), "http://example.com/telemetry.json", "http://127.0.0.1:1337"); err == nil {
		t.Fatal("foreign origin accepted")
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

func TestTelemetryUsesETWTIKernelHooksAndCoverage(t *testing.T) {
	db := openTestTelemetry(t)
	fixture := `[
	 {"type":"meta","func":"init","trace_id":9,"do_etw":true,"do_etwti":true,"do_kernel":true,"do_hook":true},
	 {"type":"process_query","func":"peb","pid":100,"image_path":"C:\\Users\\Public\\sample.exe","event_time":134382680109164370},
	 {"type":"etw","event":"KERNEL_THREATINT_TASK_WRITEVM","etw_provider_name":"Microsoft-Windows-Threat-Intelligence","etw_pid":100,"callingprocessid":100,"targetprocessid":200,"baseaddress":4096,"bytescopied":4096,"etw_time":134382680150000000},
	 {"type":"etw","event":"KERNEL_THREATINT_TASK_PROTECTVM","etw_provider_name":"Microsoft-Windows-Threat-Intelligence","etw_pid":100,"callingprocessid":100,"targetprocessid":200,"baseaddress":4096,"regionsize":4096,"protectionmask":"R-X","lastprotectionmask":"RW-","etw_time":134382680151000000},
	 {"type":"etw","event":"KERNEL_THREATINT_TASK_SUSPENDRESUME_THREAD","etw_provider_name":"Microsoft-Windows-Threat-Intelligence","etw_pid":100,"callingprocessid":100,"targetprocessid":200,"targetthreadid":201,"etw_time":134382680152000000},
	 {"type":"etw","event":"KERNEL_THREATINT_TASK_READVM","etw_provider_name":"Microsoft-Windows-Threat-Intelligence","etw_pid":100,"callingprocessid":100,"targetprocessid":200,"regionsize":4096,"etw_time":134382680153000000},
	 {"type":"dll","func":"NtProtectVirtualMemory","pid":100,"tid":101,"addr":4096,"size":4096,"protect":"R-X","return":0,"time":134382680154000000},
	 {"type":"kernel","func":"thread_create","pid":200,"krn_pid":100,"ppid":100,"threadid":201,"event_time":134382680155000000},
	 {"type":"etw","event":"KERNEL_NETWORK_TASK_TCPIPConnection attempted.","etw_provider_name":"Microsoft-Windows-Kernel-Network","etw_pid":100,"saddr":16777343,"daddr":134744072,"sport":50000,"dport":443,"size":1200,"etw_time":134382680156000000},
	 {"type":"etw","event":"KERNEL_NETWORK_TASK_TCPIPConnection attempted.","etw_provider_name":"Microsoft-Windows-Kernel-Network","etw_pid":999,"etw_process":"MsMpEng.exe","saddr":1,"daddr":2,"sport":1,"dport":2,"etw_time":134382680157000000}
	]`
	trace, err := db.Import(context.Background(), []byte(fixture), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if trace.PayloadPID != 100 || trace.Attribution != "peb" {
		t.Fatalf("attribution = %+v", trace)
	}
	delivered := strings.Join(trace.Coverage.Delivered, ",")
	for _, source := range []string{"etw", "etwti", "kernel", "hook"} {
		if !strings.Contains(delivered, source) {
			t.Fatalf("coverage missing %s: %+v", source, trace.Coverage)
		}
	}
	if len(trace.Coverage.Missing) != 0 {
		t.Fatalf("coverage = %+v", trace.Coverage)
	}
	findings, err := db.Findings(context.Background(), trace.ID)
	if err != nil {
		t.Fatal(err)
	}
	rules := findingRules(findings)
	for _, rule := range []string{
		"telemetry/cross-process-write", "telemetry/cross-process-protect",
		"telemetry/thread-suspend", "telemetry/readvm", "telemetry/hook",
		"telemetry/remote-thread", "telemetry/network",
	} {
		if _, ok := rules[rule]; !ok {
			t.Fatalf("missing %s in %+v", rule, findings)
		}
	}
	if rules["telemetry/cross-process-write"].Severity != "high" {
		t.Fatalf("write finding = %+v", rules["telemetry/cross-process-write"])
	}
	if rules["telemetry/hook"].Indicator != "NtProtectVirtualMemory" {
		t.Fatalf("hook finding = %+v", rules["telemetry/hook"])
	}
	var memory, hook, ambient int
	if err := db.db.QueryRow(`SELECT count(*) FROM events WHERE trace_pk = ? AND category = 'memory'`, trace.ID).Scan(&memory); err != nil {
		t.Fatal(err)
	}
	if err := db.db.QueryRow(`SELECT count(*) FROM events WHERE trace_pk = ? AND category = 'hook'`, trace.ID).Scan(&hook); err != nil {
		t.Fatal(err)
	}
	if err := db.db.QueryRow(`SELECT count(*) FROM events WHERE trace_pk = ? AND payload_role = 'ambient'`, trace.ID).Scan(&ambient); err != nil {
		t.Fatal(err)
	}
	if memory != 4 || hook != 1 || ambient != 1 {
		t.Fatalf("memory=%d hook=%d ambient=%d", memory, hook, ambient)
	}
	var stored int
	if err := db.db.QueryRow(`SELECT count(*) FROM findings WHERE trace_pk = ?`, trace.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != len(findings) {
		t.Fatalf("stored findings = %d, returned %d", stored, len(findings))
	}
	stats, err := db.Stats(context.Background(), trace.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stats.PayloadEvents < 7 || stats.SignalEvents == 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestTelemetryUnknownAttributionExcludesScannerEvents(t *testing.T) {
	db := openTestTelemetry(t)
	fixture := `[
	 {"type":"meta","func":"init","trace_id":10},
	 {"type":"process_query","func":"peb","pid":3112,"image_path":"","process_name":"MsMpEng.exe","event_time":134382680109164370},
	 {"type":"etw","event":"Info","etw_event_id":5,"etw_provider_name":"Microsoft-Windows-Kernel-Audit-API-Calls","etw_pid":3112,"targetprocessid":100,"desiredaccess":2035711,"event_time":134382680150000000}
	]`
	trace, err := db.Import(context.Background(), []byte(fixture), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if trace.Attribution != "unknown" || trace.PayloadPID != 0 {
		t.Fatalf("trace = %+v", trace)
	}
	findings, err := db.Findings(context.Background(), trace.ID)
	if err != nil {
		t.Fatal(err)
	}
	rules := findingRules(findings)
	if _, ok := rules["telemetry/process-access"]; ok {
		t.Fatalf("scanner event was attributed to the payload: %+v", findings)
	}
	if rules["telemetry/attribution"].Severity != "low" {
		t.Fatalf("attribution finding = %+v", rules["telemetry/attribution"])
	}
}

func TestTelemetryMergesFindingsAndRawOutput(t *testing.T) {
	db := openTestTelemetry(t)
	peb := map[string]any{
		"type": "process_query", "func": "peb", "pid": 100,
		"image_path": `C:\Users\Public\sample.exe`, "event_time": 134382680109164370,
	}
	raw := "INFO starting\n" +
		`{"type":"process_query","func":"peb","pid":100,"image_path":"C:\\Users\\Public\\sample.exe","event_time":134382680109164370}` + "\n" +
		`{"type":"kernel","func":"image_load","pid":100,"name":"C:\\Users\\Public\\stage.dll","event_time":134382680150000000}` + "\n" +
		`{"type":"dll","func":"NtWriteVirtualMemory","pid":100,"tid":101,"addr":4096,"size":32,"return":0,"time":134382680151000000}`
	wrapped, err := json.Marshal(map[string]any{"rededr": map[string]any{
		"findings":   map[string]any{"events": []any{peb}},
		"raw_output": raw,
	}})
	if err != nil {
		t.Fatal(err)
	}
	trace, err := db.Import(context.Background(), wrapped, ImportOptions{Source: "litterbox-rededr"})
	if err != nil {
		t.Fatal(err)
	}
	if trace.Events != 3 {
		t.Fatalf("events = %d", trace.Events)
	}
	result, err := db.Query(context.Background(), `SELECT category, count(*) FROM events GROUP BY category ORDER BY category`, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 3 {
		t.Fatalf("categories = %+v", result.Rows)
	}
}

func TestTelemetryMigratesV1Database(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telemetry.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	v1 := `
CREATE TABLE payloads (
  id INTEGER PRIMARY KEY AUTOINCREMENT, payload_key TEXT NOT NULL UNIQUE,
  sha256 TEXT NOT NULL DEFAULT '', module TEXT NOT NULL DEFAULT '',
  label TEXT NOT NULL DEFAULT '', artifact_path TEXT NOT NULL DEFAULT '',
  table_name TEXT NOT NULL DEFAULT '', parent_id INTEGER, created_at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE traces (
  id INTEGER PRIMARY KEY AUTOINCREMENT, payload_id INTEGER, run_id TEXT NOT NULL DEFAULT '',
  external_id TEXT NOT NULL DEFAULT '', module TEXT NOT NULL DEFAULT '',
  artifact_sha256 TEXT NOT NULL DEFAULT '', source TEXT NOT NULL,
  captured_at INTEGER NOT NULL DEFAULT 0, path TEXT NOT NULL DEFAULT '',
  meta TEXT NOT NULL DEFAULT '{}', UNIQUE(run_id, source, external_id));
CREATE TABLE events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, payload_id INTEGER, trace_pk INTEGER NOT NULL,
  ts_ns INTEGER, type TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '',
  event TEXT NOT NULL DEFAULT '', provider TEXT NOT NULL DEFAULT '',
  pid INTEGER, tid INTEGER, process TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL DEFAULT '', image TEXT NOT NULL DEFAULT '',
  address INTEGER, size INTEGER, category TEXT NOT NULL DEFAULT 'other',
  severity TEXT NOT NULL DEFAULT '', attrs TEXT NOT NULL DEFAULT '{}');
INSERT INTO payloads(payload_key, sha256, module, label, artifact_path, table_name, created_at)
  VALUES('sha256:deadbeef', 'deadbeef', 'loader_windows', 'sample.exe', '/tmp/sample.exe', 'payload_0000000000000000', 1);
INSERT INTO traces(payload_id, run_id, external_id, module, artifact_sha256, source, captured_at, path, meta)
  VALUES(1, 'run-v1', 'trace:1', 'loader_windows', 'deadbeef', 'rededr', 1, '/tmp/t.json', '{}');
INSERT INTO events(payload_id, trace_pk, type, source, event, provider, pid, category, attrs)
  VALUES(1, 1, 'process_query', 'rededr', 'peb', '', 100, 'query',
    '{"type":"process_query","func":"peb","pid":100,"image_path":"C:\\\\Users\\\\Public\\\\sample.exe","event_time":134382680109164370}');
INSERT INTO events(payload_id, trace_pk, type, source, event, provider, pid, category, attrs)
  VALUES(1, 1, 'etw', 'rededr', 'KERNEL_THREATINT_TASK_WRITEVM', 'Microsoft-Windows-Threat-Intelligence', 100, 'other',
    '{"type":"etw","event":"KERNEL_THREATINT_TASK_WRITEVM","etw_provider_name":"Microsoft-Windows-Threat-Intelligence","etw_pid":100,"callingprocessid":100,"targetprocessid":200,"bytescopied":4096,"event_time":134382680150000000}');
PRAGMA user_version = 1;
`
	if _, err := raw.Exec(v1); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := OpenTelemetryDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	if err := db.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != TelemetrySchemaVersion {
		t.Fatalf("version = %d", version)
	}
	var pid int64
	var attribution string
	if err := db.db.QueryRow(`SELECT COALESCE(payload_pid, 0), attribution FROM traces WHERE id = 1`).Scan(&pid, &attribution); err != nil {
		t.Fatal(err)
	}
	if pid != 100 || attribution != "peb" {
		t.Fatalf("payload pid=%d attribution=%q", pid, attribution)
	}
	var category, role, signal string
	if err := db.db.QueryRow(`SELECT category, payload_role, signal FROM events WHERE trace_pk = 1 AND provider <> ''`).Scan(&category, &role, &signal); err != nil {
		t.Fatal(err)
	}
	if category != "memory" || role != "payload" || signal != "signal" {
		t.Fatalf("event category=%q role=%q signal=%q", category, role, signal)
	}
	findings, err := db.Findings(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if findings == nil || findingRules(findings)["telemetry/cross-process-write"].Severity != "high" {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestFetchTelemetryStaysOnSandboxOrigin(t *testing.T) {
	var foreignHits atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignHits.Add(1)
		fmt.Fprint(w, `[{"type":"meta","trace_id":1}]`)
	}))
	defer foreign.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, foreign.URL, http.StatusFound)
			return
		}
		fmt.Fprint(w, `[{"type":"meta","trace_id":1}]`)
	}))
	defer origin.Close()

	if _, err := FetchTelemetry(context.Background(), origin.URL+"/redirect", origin.URL); err == nil {
		t.Fatal("telemetry redirect to another origin was accepted")
	}
	if foreignHits.Load() != 0 {
		t.Fatalf("foreign origin was contacted %d times", foreignHits.Load())
	}
	if _, err := FetchTelemetry(context.Background(), origin.URL+"/ok", origin.URL); err != nil {
		t.Fatalf("same-origin telemetry failed: %v", err)
	}
}

func TestImportSandboxStoresEveryAnalyzer(t *testing.T) {
	db := openTestTelemetry(t)
	results := SandboxResults{
		Info: json.RawMessage(`{"original_name":"sample.exe","md5":"deadbeef"}`),
		Static: json.RawMessage(`{
			"yara":{"matches":[{"rule":"test_rule"}]},
			"checkplz":{"findings":{"initial_threat":true}}
		}`),
		Dynamic: json.RawMessage(`{
			"rededr":{"findings":{"events":[
				{"type":"process_query","func":"peb","id":2,"pid":8216,
				 "parent_pid":42,"image_path":"C:\\Users\\Public\\sample.exe",
				 "trace_id":41,"event_time":134382680109164370}
			]}},
			"moneta":{"findings":{"total_private_rwx":1}},
			"pe_sieve":{"findings":{"total_suspicious":2}},
			"hsb":{"findings":{"total_findings":1}},
			"patriot":{"findings":[{"description":"test"}]},
			"blender":{"findings":{"test":true}}
		}`),
		HolyGrail: json.RawMessage(`{"findings":{"vulnerable":true}}`),
		EDR: map[string]json.RawMessage{
			"elastic": json.RawMessage(`{"alerts":[{"rule":"test"}]}`),
		},
	}
	trace, err := db.ImportSandbox(context.Background(), results, ImportOptions{
		RunID: "loader_windows-all-analyzers", Module: "loader_windows", ArtifactSHA256: "deadbeef",
	})
	if err != nil {
		t.Fatal(err)
	}
	if trace.Source != "sandbox" {
		t.Fatalf("source = %q", trace.Source)
	}
	if trace.Events < 11 {
		t.Fatalf("events = %d, want at least 11", trace.Events)
	}
	if trace.Coverage.Categories["analysis"] == 0 {
		t.Fatalf("analysis coverage = %+v", trace.Coverage)
	}
	findings, err := db.Findings(context.Background(), trace.ID)
	if err != nil {
		t.Fatal(err)
	}
	rules := findingRules(findings)
	for _, rule := range []string{
		"analyzer/static/yara", "analyzer/static/checkplz",
		"analyzer/dynamic/moneta", "analyzer/dynamic/pe_sieve",
		"analyzer/dynamic/hsb", "analyzer/dynamic/patriot",
		"analyzer/dynamic/blender", "analyzer/holygrail",
		"analyzer/edr/elastic",
	} {
		if _, ok := rules[rule]; !ok {
			t.Fatalf("missing finding %q in %+v", rule, rules)
		}
	}
}

func TestFetchResultsFetchesEveryBlock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/results/info/hash":
			fmt.Fprint(w, `{"name":"sample.exe"}`)
		case "/api/results/static/hash":
			fmt.Fprint(w, `{"yara":{"matches":[]}}`)
		case "/api/results/dynamic/hash":
			fmt.Fprint(w, `{"rededr":{"findings":{"events":[]}}}`)
		case "/api/results/holygrail/hash":
			fmt.Fprint(w, `{"findings":{}}`)
		case "/api/results/edr/hash":
			fmt.Fprint(w, `{"profiles":["elastic"]}`)
		case "/api/results/edr/elastic/hash":
			fmt.Fprint(w, `{"alerts":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	results := client.FetchResults(context.Background(), "hash", nil, nil)
	if len(results.Info) == 0 || len(results.Static) == 0 || len(results.Dynamic) == 0 || len(results.HolyGrail) == 0 {
		t.Fatalf("missing result block: %+v", results)
	}
	if len(results.EDR["elastic"]) == 0 {
		t.Fatalf("missing EDR result: %+v", results)
	}
	if len(results.Warnings) != 0 {
		t.Fatalf("warnings = %v", results.Warnings)
	}
}

func TestFetchResultsCapsEDRProfiles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/results/edr/hash":
			profiles := make([]string, 50)
			for i := range profiles {
				profiles[i] = fmt.Sprintf("profile%d", i)
			}
			data, _ := json.Marshal(map[string]any{"profiles": profiles})
			w.Write(data)
		case strings.HasPrefix(r.URL.Path, "/api/results/edr/"):
			fmt.Fprint(w, `{"alerts":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	results := client.FetchResults(context.Background(), "hash", json.RawMessage(`{}`), json.RawMessage(`{}`))
	if len(results.EDR) != maxFetchedEDRProfiles {
		t.Fatalf("got %d EDR profiles, want %d", len(results.EDR), maxFetchedEDRProfiles)
	}
	foundTruncated := false
	for _, warning := range results.Warnings {
		if strings.Contains(warning, "truncated") {
			foundTruncated = true
			break
		}
	}
	if !foundTruncated {
