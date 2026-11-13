package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/detection"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/opsec"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func fakeDetectionSandbox(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	dynamicCalls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/health":
			fmt.Fprint(w, `{"scanners": {"rows": [
			  {"group":"static","name":"yara","status":"ok","enabled":true,"exists":true},
			  {"group":"dynamic","name":"pe_sieve","status":"ok","enabled":true,"exists":true}]},
			  "edr_agents": {"agents":[]}, "issues": []}`)
		case r.URL.Path == "/api/edr/profiles":
			fmt.Fprint(w, `{"profiles": []}`)
		case r.URL.Path == "/upload":
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Errorf("multipart: %v", err)
			}
			fmt.Fprint(w, `{"file_info": {"md5": "d41d8cd98f00b204e9800998ecf8427e", "sha256": "abc", "size": 9, "original_name": "loader.exe"}}`)
		case strings.HasPrefix(r.URL.Path, "/analyze/static/"):
			fmt.Fprint(w, `{"status": "success", "results": {
			  "yara": {"matches": [{"rule": "test_rule", "meta": {"severity": "HIGH"},
			    "strings": [{"data": "VirtualAllocEx"}]}]},
			  "stringnalyzer": {"findings": {"found_suspicious_strings": ["marker"]}}}}`)
		case strings.HasPrefix(r.URL.Path, "/analyze/dynamic/"):
			dynamicCalls.Add(1)
			fmt.Fprint(w, `{"status": "success"}`)
		case strings.HasPrefix(r.URL.Path, "/api/results/dynamic/"):
			fmt.Fprint(w, `{"status": "completed", "rededr": {"findings": {"events": [
			  {"type":"process_query","func":"peb","pid":100,"image_path":"C:\\Users\\x\\loader.exe"},
			  {"type":"etw","event":"ProcessStartStart ","etw_provider_name":"Microsoft-Windows-Kernel-Process",
			   "etw_pid":100,"processid":200,"imagename":"\\Device\\HarddiskVolume3\\Users\\x\\Temp\\a.exe","trace_id":9,
			   "event_time":134382680150000000}]}}}`)
		case strings.HasPrefix(r.URL.Path, "/api/results/risk/"):
			fmt.Fprint(w, `{"risk_score": 50, "risk_level": "Medium", "risk_factors": ["yara"]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, dynamicCalls
}

func detectionTestActions(t *testing.T, serverURL string) *Actions {
	t.Helper()
	loop, err := detection.NewLoop(detection.LoopConfig{SandboxURL: serverURL, StoreRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := OpenAudit(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.Close() })
	return &Actions{
		Policy:    opsec.DefaultPolicy(),
		Audit:     audit,
		Limiter:   NewLimiter(60, 5),
		Detection: loop,
		Operator:  "test",
	}
}

func writeArtifact(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "loader.exe")
	if err := os.WriteFile(path, []byte("MZpayload"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAttachDetectionAfterBuild(t *testing.T) {
	server, _ := fakeDetectionSandbox(t)
	actions := detectionTestActions(t, server.URL)
	dir := t.TempDir()
	artifact := writeArtifact(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "bootstrap.c"), []byte("void f(void) { VirtualAllocEx(0,0,0,0,0); char *m = \"marker\"; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mod := &def.ModuleConfig{Name: "loader_windows", Path: dir, Platform: "Windows"}
	buildLog := fmt.Sprintf("ok\n[+] generated payload: %s (%d bytes)\n", artifact, 9)
	block := actions.attachDetection(context.Background(), mod, buildLog)
	if block == nil {
		t.Fatal("no detection block")
	}
	runID, _ := block["run_id"].(string)
	if runID == "" {
		t.Fatalf("block = %+v", block)
	}
	if block["status"] != "completed" {
		t.Fatalf("status = %v", block["status"])
	}
	feedback, err := actions.Detection.Feedback(runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(feedback.Findings) < 2 {
		t.Fatalf("findings = %+v", feedback.Findings)
	}
	if _, ok := actions.Detection.Store.KnownArtifact("loader_windows", artifact); !ok {
		t.Fatal("artifact was not recorded")
	}
}

func TestDetectionRunHandlerScreensExecution(t *testing.T) {
	server, dynamicCalls := fakeDetectionSandbox(t)
	actions := detectionTestActions(t, server.URL)
	dir := t.TempDir()
	artifact := writeArtifact(t, dir)
	if err := actions.Detection.Store.RecordArtifact("loader_windows", mustInspect(t, artifact)); err != nil {
		t.Fatal(err)
	}
	mod := &def.ModuleConfig{Name: "loader_windows", Path: dir, Platform: "Windows"}
	def.Modules.Store(mod.Name, mod)
	t.Cleanup(func() { def.Modules.Delete(mod.Name) })

	args, _ := json.Marshal(map[string]any{"module": "loader_windows", "artifact": artifact})
	result, err := actions.detectionRun(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	payload := result.(map[string]any)
	if payload["run_id"] == nil || payload["feedback"] == nil {
		t.Fatalf("result = %+v", payload)
	}
	if dynamicCalls.Load() != 0 {
		t.Fatalf("dynamic ran without approval: %d", dynamicCalls.Load())
	}

	activeArgs, _ := json.Marshal(map[string]any{"module": "loader_windows", "artifact": artifact, "stages": []string{"dynamic"}})
	if _, err := actions.detectionRun(context.Background(), activeArgs); err == nil {
		t.Fatal("dynamic without approval was accepted")
	}
}

func TestDetectionRejectsUnrecordedArtifact(t *testing.T) {
	server, _ := fakeDetectionSandbox(t)
	actions := detectionTestActions(t, server.URL)
	dir := t.TempDir()
	artifact := writeArtifact(t, dir)
	mod := &def.ModuleConfig{Name: "loader_windows", Path: dir, Platform: "Windows"}
	def.Modules.Store(mod.Name, mod)
	t.Cleanup(func() { def.Modules.Delete(mod.Name) })
	if _, _, err := actions.resolveDetectionArtifact("loader_windows", artifact); err == nil {
		t.Fatal("unrecorded artifact accepted")
	}
}

func mustInspect(t *testing.T, path string) detection.Artifact {
	t.Helper()
	artifact, err := detection.InspectArtifact(path)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func TestDetectionFeedbackReportsMissingAnalyst(t *testing.T) {
	server, _ := fakeDetectionSandbox(t)
	actions := detectionTestActions(t, server.URL)
	dir := t.TempDir()
	artifact := writeArtifact(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "bootstrap.c"), []byte("VirtualAllocEx(0,0,0,0,0);\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mod := &def.ModuleConfig{Name: "loader_windows", Path: dir, Platform: "Windows"}
	block := actions.attachDetection(context.Background(), mod, fmt.Sprintf("[+] generated payload: %s (%d bytes)\n", artifact, 9))
	runID, _ := block["run_id"].(string)
	if runID == "" {
		t.Fatalf("block = %+v", block)
	}
	args, _ := json.Marshal(map[string]any{"run_id": runID, "analyze": true})
	result, err := actions.detectionFeedback(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	payload := result.(map[string]any)
	if payload["analysis_error"] == nil {
		t.Fatalf("missing analyst error: %+v", payload)
	}
}

func TestDetectionTelemetryImportAndQuery(t *testing.T) {
	server, _ := fakeDetectionSandbox(t)
	actions := detectionTestActions(t, server.URL)
	path := filepath.Join(t.TempDir(), "rededr.json")
	fixture := `[{"type":"meta","trace_id":9,"event_time":134382680038271379},
	 {"type":"etw","event":"ProcessStartStart ","etw_provider_name":"Microsoft-Windows-Kernel-Process",
	  "etw_pid":100,"processid":200,"imagename":"\\Device\\HarddiskVolume3\\Users\\x\\Temp\\a.exe",
	  "trace_id":9,"event_time":134382680150000000},
	 {"type":"etw","event":"Behavior Monitoring BmDetection","etw_provider_name":"Microsoft-Antimalware-Engine",
	  "etw_pid":300,"processid":100,"name":"Behavior:Win32/TestInject.A",
	  "imagepath":"C:\\Users\\x\\Temp\\a.exe","trace_id":9,"event_time":134382680160000000}]`
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"path": path})
	imported, err := actions.detectionImport(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	result, ok := imported.(map[string]any)
	if !ok {
		t.Fatalf("import result = %T", imported)
	}
	trace, ok := result["trace"].(detection.TelemetryTrace)
	if !ok || trace.Events != 2 {
		t.Fatalf("trace = %+v", result["trace"])
	}
	findings, _ := result["findings"].([]detection.Finding)
	if len(findings) == 0 {
		t.Fatal("no findings")
	}
	query, _ := json.Marshal(map[string]any{
		"sql": "SELECT event, category FROM events ORDER BY id", "limit": 10,
	})
	queried, err := actions.detectionQuery(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	rows := queried.(detection.QueryResult)
	if len(rows.Rows) != 2 || rows.Columns[0] != "event" {
		t.Fatalf("query = %+v", rows)
	}
	payloads, err := actions.detectionPayloads(context.Background(), json.RawMessage(`{"limit":10}`))
	if err != nil {
		t.Fatal(err)
	}
	list, _ := payloads.(map[string]any)["payloads"].([]detection.Payload)
	if len(list) != 1 || list[0].Table == "" || list[0].Key != trace.PayloadKey {
		t.Fatalf("payloads = %+v", payloads)
	}
	diff, err := actions.detectionCompare(context.Background(), json.RawMessage(
		`{"from":"`+trace.PayloadKey+`","to":"`+trace.PayloadKey+`"}`))
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if diff.(detection.PayloadDiff).From.Key != trace.PayloadKey {
		t.Fatalf("diff = %+v", diff)
	}
}

func TestDetectionRunIngestsDynamicTelemetry(t *testing.T) {
	server, _ := fakeDetectionSandbox(t)
	actions := detectionTestActions(t, server.URL)
	dir := t.TempDir()
	artifact := writeArtifact(t, dir)
	if err := actions.Detection.Store.RecordArtifact("loader_windows", mustInspect(t, artifact)); err != nil {
		t.Fatal(err)
	}
	mod := &def.ModuleConfig{Name: "loader_windows", Path: dir, Platform: "Windows"}
	def.Modules.Store(mod.Name, mod)
	t.Cleanup(func() { def.Modules.Delete(mod.Name) })

	args, _ := json.Marshal(map[string]any{
		"module": "loader_windows", "artifact": artifact,
		"stages": []string{"dynamic"}, "approve_execution": true,
	})
	result, err := actions.detectionRun(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	payload := result.(map[string]any)
	telemetry, ok := payload["telemetry"].(*detection.TelemetryRun)
	if !ok || telemetry.Events != 2 || telemetry.TraceID == 0 {
		t.Fatalf("telemetry = %+v", payload["telemetry"])
	}
	if telemetry.Findings == nil {
		t.Fatalf("missing telemetry findings: %+v", telemetry)
	}
}

func TestDetectionLoopRequiresApproval(t *testing.T) {
	server, _ := fakeDetectionSandbox(t)
	actions := detectionTestActions(t, server.URL)
	args, _ := json.Marshal(map[string]any{
		"module_dir": t.TempDir(), "shellcode": "/tmp/nonexistent.bin",
	})
	if _, err := actions.detectionLoop(context.Background(), args); err == nil {
		t.Fatal("detection_loop ran without approve_execution")
	}
}
