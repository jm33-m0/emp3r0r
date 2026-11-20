package detection

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

const litterBoxPayloadTrace = `[
 {"type":"meta","func":"init","trace_id":41,"version":"1.0","do_etw":true,"do_etwti":true,
  "do_antimalwareengine":false,"targets":["malware"],"event_time":134395611380000000},
 {"type":"process_query","func":"peb","id":13,"pid":4456,"parent_pid":4928,
  "image_path":"C:\\LitterBox\\Uploads\\payload.exe","working_dir":"C:\\LitterBox\\",
  "is_debugged":0,"is_protected_process":0,"trace_id":41,"event_time":134395611386000000},
 {"type":"etw","event":"ProcessStartStart ","etw_provider_name":"Microsoft-Windows-Kernel-Process",
  "etw_pid":4456,"etw_tid":4288,"processid":5356,"parentprocessid":4456,
  "imagename":"\\Device\\HarddiskVolume3\\Windows\\System32\\dllhost.exe",
  "trace_id":41,"event_time":134395611386100000},
 {"type":"etw","event":"ThreadStartStart ","etw_provider_name":"Microsoft-Windows-Kernel-Process",
  "etw_pid":4456,"etw_tid":4288,"processid":5356,"threadid":4396,
  "trace_id":41,"event_time":134395611386200000},
 {"type":"etw","event":"KERNEL_THREATINT_TASK_WRITEVM",
  "etw_provider_name":"Microsoft-Windows-Threat-Intelligence",
  "etw_pid":4456,"callingprocessid":4456,"targetprocessid":5356,
  "baseaddress":2277431312384,"bytescopied":9444801,
  "trace_id":41,"event_time":134395611386300000},
 {"type":"etw","event":"KERNEL_THREATINT_TASK_PROTECTVM",
  "etw_provider_name":"Microsoft-Windows-Threat-Intelligence",
  "etw_pid":4456,"callingprocessid":4456,"targetprocessid":5356,
  "baseaddress":2277431312384,"regionsize":9444833,"protectionmask":"R-X",
  "trace_id":41,"event_time":134395611386400000},
 {"type":"etw","event":"KERNEL_THREATINT_TASK_SUSPENDRESUME_THREAD",
  "etw_provider_name":"Microsoft-Windows-Threat-Intelligence",
  "etw_pid":4456,"callingprocessid":4456,"targetprocessid":5356,"targetthreadid":4396,
  "trace_id":41,"event_time":134395611386500000},
 {"type":"etw","event":"PspLogAuditOpenProcessEvent",
  "etw_provider_name":"Microsoft-Windows-Kernel-Audit-API-Calls",
  "etw_event_id":5,"etw_pid":2592,"targetprocessid":4456,"desiredaccess":2035711,
  "trace_id":41,"event_time":134395611386600000}
]`

func TestLitterBoxUploadIsThePayloadNotAScanner(t *testing.T) {
	if looksLikeScanner(`C:\LitterBox\Uploads\payload.exe`) {
		t.Fatal("the payload upload path was treated as a scanner")
	}
	if !looksLikeScanner(`C:\LitterBox\Scanners\Moneta\moneta.exe`) {
		t.Fatal("an analyzer path was not treated as a scanner")
	}
	if isAmbientImage(`C:\LitterBox\Uploads\payload.exe`, "payload", "") {
		t.Fatal("the payload upload path was treated as ambient")
	}
}

func TestRedEdrAttributionUnlocksBehavioralFindings(t *testing.T) {
	db := openTestTelemetry(t)
	trace, err := db.Import(context.Background(), []byte(litterBoxPayloadTrace), ImportOptions{
		Source: "rededr", RunID: "loader_windows-litterbox",
		Module: "loader_windows", ArtifactSHA256: "deadbeef",
	})
	if err != nil {
		t.Fatal(err)
	}
	if trace.Attribution != "peb" || trace.PayloadPID != 4456 {
		t.Fatalf("attribution = %q pid = %d, want peb/4456", trace.Attribution, trace.PayloadPID)
	}
	if !strings.Contains(strings.ToLower(trace.PayloadImage), `\litterbox\uploads\`) {
		t.Fatalf("payload image = %q", trace.PayloadImage)
	}
	findings, err := db.Findings(context.Background(), trace.ID)
	if err != nil {
		t.Fatal(err)
	}
	rules := findingRules(findings)
	for rule, severity := range map[string]string{
		"telemetry/cross-process-write":   "high",
		"telemetry/cross-process-protect": "high",
		"telemetry/thread-suspend":        "high",
		"telemetry/remote-thread":         "medium",
		"telemetry/child-process":         "medium",
	} {
		finding, ok := rules[rule]
		if !ok {
			t.Fatalf("missing %s in %+v", rule, findings)
		}
		if finding.Severity != severity {
			t.Fatalf("%s severity = %q, want %q", rule, finding.Severity, severity)
		}
	}
	for _, rule := range []string{"telemetry/attribution", "telemetry/unattributed-etwti", "telemetry/unattributed-process"} {
		if _, ok := rules[rule]; ok {
			t.Fatalf("unexpected unattributed finding %s: %+v", rule, rules[rule])
		}
	}
}

func TestRedEdrBehavioralFindingIsActionableWithoutSource(t *testing.T) {
	finding := Finding{
		Stage: StageTelemetry, Tool: "telemetry", Severity: "high",
		Rule: "telemetry/cross-process-write", Indicator: "WriteProcessMemory",
	}
	if !actionableFinding(finding) {
		t.Fatal("high behavioral telemetry was not actionable without a source location")
	}
	coverage := Finding{
		Stage: StageTelemetry, Tool: "telemetry", Severity: "medium",
		Rule: "telemetry/coverage", Indicator: "missing analyzer",
	}
	if actionableFinding(coverage) {
		t.Fatal("coverage metadata was treated as an actionable detection")
	}
}

func TestTelemetrySourceHint(t *testing.T) {
	finding := Finding{Stage: StageTelemetry, Rule: "telemetry/cross-process-protect"}
	hint := telemetrySourceHint(finding)
	if hint != "VirtualProtect" {
		t.Fatalf("source hint = %q", hint)
	}
	finding.SourceHint = hint
	encoded, _ := json.Marshal(finding)
	if strings.Contains(string(encoded), "VirtualProtect") {
		t.Fatalf("internal source hint leaked into JSON: %s", encoded)
	}
}
