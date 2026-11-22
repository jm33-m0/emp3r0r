package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

const stagerLinuxBuildOptionConfig = `[
  {
    "name": "stager_linux",
    "build": "bash ./build.sh",
    "is_local": true,
    "platform": "Linux",
    "parameters": [
      {"name": "format", "type": "string", "default": "raw", "choices": ["so", "executable", "raw", "packed"]},
      {"name": "agent-pic", "type": "string", "default": ""},
      {"name": "transport", "type": "string", "default": "http", "choices": ["http", "tcp", "udp"]},
      {"name": "unpacker", "type": "string", "default": "rc4", "choices": ["rc4", "lzss"]}
    ]
  }
]`

func TestNormalizeEvolveConfigAcceptsLinuxPayload(t *testing.T) {
	root := t.TempDir()
	moduleDir := filepath.Join(root, "core", "modules", "stager_linux")
	agentDir := filepath.Join(root, "core", "c_agent")
	for _, dir := range []string{moduleDir, agentDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	pic := filepath.Join(t.TempDir(), "agent.bin")
	if err := os.WriteFile(pic, []byte("pic"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := EvolveConfig{
		Module: "stager_linux", ModuleDir: moduleDir, Shellcode: pic,
		StoreRoot: t.TempDir(), Format: "exe",
	}
	if err := normalizeEvolveConfig(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Platform != platformLinux || cfg.AgentType != "linux_so" {
		t.Fatalf("platform/type = %q/%q", cfg.Platform, cfg.AgentType)
	}
	if cfg.Format != "executable" || cfg.SMW != "" || cfg.Process != "" || cfg.Inject != "" {
		t.Fatalf("unexpected Windows build state: %+v", cfg)
	}
	if cfg.AgentSourceDir != agentDir {
		t.Fatalf("agent source = %q, want %q", cfg.AgentSourceDir, agentDir)
	}
	if len(cfg.ProducerDirs) != 0 {
		t.Fatalf("producers = %v, want none", cfg.ProducerDirs)
	}
}

func TestNormalizeEvolveConfigRejectsCustomMalasadaPath(t *testing.T) {
	root := t.TempDir()
	moduleDir := filepath.Join(root, "core", "modules", "stager_linux")
	agentDir := filepath.Join(root, "core", "c_agent")
	malasadaDir := filepath.Join(root, "core", "modules", "malasada")
	for _, dir := range []string{moduleDir, agentDir, malasadaDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(malasadaDir, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	pic := filepath.Join(t.TempDir(), "agent.bin")
	if err := os.WriteFile(pic, []byte("pic"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := EvolveConfig{
		Module: "stager_linux", ModuleDir: moduleDir, Shellcode: pic,
		StoreRoot: t.TempDir(), AgentSourceDir: agentDir,
		ProducerDirs: map[string]string{"malasada": filepath.Join(root, "elsewhere")},
		BuildAgent: func(AgentBuildOptions) (*AgentBuildResult, error) {
			return nil, nil
		},
	}
	if err := normalizeEvolveConfig(&cfg); err == nil {
		t.Fatal("a custom malasada path was accepted")
	}
}

func TestLinuxPayloadBuildFlags(t *testing.T) {
	moduleDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(moduleDir, "config.json"), []byte(stagerLinuxBuildOptionConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &evolver{
		cfg: EvolveConfig{
			Module: "stager_linux", ModuleDir: moduleDir, Format: "executable",
		},
		logf: func(logging.Class, string, ...any) {},
	}
	e.initBuildOptions(map[string]string{
		"format": "raw", "agent-pic": "ignored", "transport": "tcp",
		"process": "must-not-pass", "arch": "x64", "shellcode": "ignored",
	})
	flags := e.payloadBuildFlags("/tmp/agent.bin", 1)
	if flags["format"] != "executable" || flags["agent-pic"] != "/tmp/agent.bin" {
		t.Fatalf("host-owned flags = %v", flags)
	}
	if flags["transport"] != "tcp" {
		t.Fatalf("declared option dropped: %v", flags)
	}
	for _, key := range []string{"process", "arch", "shellcode", "output"} {
		if _, ok := flags[key]; ok {
			t.Fatalf("unexpected %s flag: %v", key, flags)
		}
	}
}

const penguinBoxDynamicFixture = `{
  "run": {"run_id":"20261122T120000Z-deadbeef","sha256":"deadbeef","artifact":"/var/lib/penguinbox/uploads/x/payload","payload_pid":0},
  "findings": {"events": [
    {"collector":"tracee","eventName":"execve","timestamp":1763812800.5,"processId":100,"parentProcessId":99,
     "processName":"payload","args":[{"name":"pathname","value":"/payload"}]},
    {"collector":"tracee","eventName":"execve","timestamp":1763812801.5,"processId":101,"parentProcessId":100,
     "processName":"dropper","args":[{"name":"pathname","value":"/tmp/dropper"}]},
    {"collector":"tracee","eventName":"memfd_create","timestamp":1763812802,"processId":100,"parentProcessId":99,
     "processName":"payload","args":[{"name":"name","value":"stub"}]},
    {"collector":"falco","time":"2026-11-22T12:00:03Z","rule":"PenguinBox memfd create","priority":"WARNING",
     "output":"memfd","output_fields":{"proc.pid":100,"proc.ppid":99,"proc.name":"payload","evt.type":"memfd_create"}}
  ]},
  "coverage": {"tracee":{"events":3},"falco":{"alerts":1},"expected":["tracee","falco"]}
}`

func TestPenguinBoxDynamicParsesTraceeAndFalco(t *testing.T) {
	parsed, ok, err := parsePenguinBoxDynamic([]byte(penguinBoxDynamicFixture))
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if parsed.Platform != platformLinux || parsed.PayloadPID != 100 || parsed.PayloadImage != "/payload" {
		t.Fatalf("payload identity = %+v", parsed)
	}
	if len(parsed.Events) != 4 {
		t.Fatalf("events = %d", len(parsed.Events))
	}
	if !containsFold(parsed.Coverage.Delivered, "tracee") || !containsFold(parsed.Coverage.Delivered, "falco") {
		t.Fatalf("coverage = %+v", parsed.Coverage)
	}
}

func TestPenguinBoxPayloadIdentityUsesGuestPID(t *testing.T) {
	events := []telemetryEvent{
		{PID: 999, Event: "sched_process_exec", Process: "unrelated", Image: "/unrelated", Category: "process", Operation: "create"},
		{PID: 42, Event: "sched_process_exec", Process: "payload", Image: "/payload", Category: "process", Operation: "create"},
	}
	pid, image := penguinBoxPayloadIdentity(events, penguinBoxHostPIDMap([]any{
		map[string]any{"eventName": "sched_process_exec", "processId": float64(999), "hostProcessId": float64(999)},
		map[string]any{"eventName": "sched_process_exec", "processId": float64(42), "hostProcessId": float64(999)},
	})[999])
	if pid != 42 || image != "/payload" {
		t.Fatalf("identity = %d %q, want 42 /payload", pid, image)
	}
}

func TestPenguinBoxDynamicCapsEvents(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"run":{"run_id":"cap-test"},"findings":{"events":[`)
	for i := 0; i <= maxTelemetryEvents; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"eventName":"openat","eventId":%d,"processId":42}`, i)
	}
	b.WriteString(`]}}`)
	_, ok, err := parsePenguinBoxDynamic([]byte(b.String()))
	if !ok {
		t.Fatal("expected PenguinBox dynamic format to be recognized")
	}
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("parsePenguinBoxDynamic err = %v, want event cap error", err)
	}
}

func TestTraceeArgIntRejectsInt64Overflow(t *testing.T) {
	if got := traceeArgInt(map[string]any{"size": "0x7fffffffffffffff"}, "size"); got != 0x7fffffffffffffff {
		t.Fatalf("max int64 = %d, want %d", got, int64(0x7fffffffffffffff))
	}
	if got := traceeArgInt(map[string]any{"size": "0x8000000000000000"}, "size"); got != 0 {
		t.Fatalf("overflow uint64 = %d, want 0", got)
	}
}

func TestLabTelemetryV1UsesOneEnvelope(t *testing.T) {
	payload := []byte(`{
  "schema":"emp3r0r.telemetry/v1","lab":"lab-box","platform":"linux",
  "run":{"id":"run-1","artifact":"/payload","payload_pid":42,"payload_image":"/payload"},
  "coverage":{"delivered":["sensor-a"],"expected":["sensor-a"]},
  "events":[
    {"timestamp":"2026-11-22T04:00:00Z","sensor":"sensor-a","event":"exec","category":"process","operation":"create","pid":42,"ppid":1,"process":"payload","path":"/payload"},
    {"timestamp":"2026-11-22T04:00:01Z","sensor":"sensor-a","event":"connect","category":"network","operation":"connect","pid":42,"dst_addr":"10.0.0.1","dst_port":443}
  ]
}`)
	parsed, err := parseTelemetry(payload, "")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Platform != platformLinux || parsed.Source != "lab-box" || parsed.PayloadPID != 42 || len(parsed.Events) != 2 {
		t.Fatalf("parsed = platform %q source %q pid %d events %d", parsed.Platform, parsed.Source, parsed.PayloadPID, len(parsed.Events))
	}
	if parsed.Events[0].Category != "process" || parsed.Events[1].DstAddr != "10.0.0.1" || parsed.Events[1].DstPort != 443 {
		t.Fatalf("events = %+v", parsed.Events)
	}
}

func TestTraceeSocketClassification(t *testing.T) {
	unixEvent := normalizeTraceeEvent(map[string]any{
		"eventName": "security_socket_connect",
		"args": []any{map[string]any{
			"name":  "remote_addr",
			"value": map[string]any{"sa_family": "AF_UNIX", "sun_path": "/var/run/nscd/socket"},
		}},
	})
	if unixEvent.Category != "ipc" || unixEvent.DstAddr != "/var/run/nscd/socket" {
		t.Fatalf("AF_UNIX event = category %q addr %q", unixEvent.Category, unixEvent.DstAddr)
	}
	inetEvent := normalizeTraceeEvent(map[string]any{
		"eventName": "security_socket_connect",
		"args": []any{map[string]any{
			"name": "remote_addr",
			"value": map[string]any{
				"sa_family": "AF_INET", "sin_addr": "10.0.2.2", "sin_port": float64(18080),
			},
		}},
	})
	if inetEvent.Category != "network" || inetEvent.DstAddr != "10.0.2.2" || inetEvent.DstPort != 18080 {
		t.Fatalf("AF_INET event = category %q addr %q port %d", inetEvent.Category, inetEvent.DstAddr, inetEvent.DstPort)
	}
}

func TestPenguinBoxSandboxFindings(t *testing.T) {
	db := openTestTelemetry(t)
	trace, err := db.ImportSandbox(context.Background(), SandboxResults{
		Dynamic: json.RawMessage(penguinBoxDynamicFixture),
	}, ImportOptions{RunID: "linux-run", Module: "stager_linux", Platform: platformLinux, Source: "sandbox"})
	if err != nil {
		t.Fatal(err)
	}
	if trace.Platform != platformLinux {
		t.Fatalf("trace platform = %q", trace.Platform)
	}
	findings, err := db.Findings(context.Background(), trace.ID)
	if err != nil {
		t.Fatal(err)
	}
	rules := findingRules(findings)
	if rules["falco/PenguinBox memfd create"].Severity == "" {
		t.Fatalf("Falco finding missing: %+v", rules)
	}
	if rules["telemetry/memfd"].Severity != "high" {
		t.Fatalf("memfd finding = %+v", rules["telemetry/memfd"])
	}
	if rules["telemetry/writable-exec"].Severity != "high" {
		t.Fatalf("writable exec finding = %+v", rules["telemetry/writable-exec"])
	}
}

func TestBuildFeedbackIndexesAgentSource(t *testing.T) {
	moduleDir := t.TempDir()
	agentDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(moduleDir, "stager.c"), []byte("int main(void) { return 0; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(agentDir, "syscalls.c"), []byte("int f(void) { return memfd_create(\"x\", 0); }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := Run{
		ID: "stager_linux-test", Module: "stager_linux",
		Plan: Plan{
			Module: "stager_linux", ModuleDir: moduleDir,
			AgentSourceDir: agentDir,
			Artifact:       Artifact{Name: "stager"},
		},
		Telemetry: &TelemetryRun{Findings: []Finding{{
			Rule: "telemetry/memfd", Indicator: "memfd_create", Severity: "high",
		}}},
	}
	feedback := BuildFeedback(run)
	if len(feedback.Findings) != 1 || len(feedback.Findings[0].Sources) == 0 {
		t.Fatalf("finding was not mapped: %+v", feedback.Findings)
	}
	if !strings.HasPrefix(feedback.Findings[0].Sources[0].File, "c_agent/") &&
		!strings.HasPrefix(feedback.Findings[0].Sources[0].File, filepath.Base(agentDir)+"/") {
		t.Fatalf("source file = %q", feedback.Findings[0].Sources[0].File)
	}
}

func TestLinuxSourceRootsAndTools(t *testing.T) {
	root := t.TempDir()
	moduleDir := filepath.Join(root, "core", "modules", "stager_linux")
	agentDir := filepath.Join(root, "core", "c_agent")
	for _, dir := range []string{moduleDir, agentDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e := &evolver{
		cfg: EvolveConfig{
			Module: "stager_linux", ModuleDir: moduleDir, AgentSourceDir: agentDir,
			Platform: platformLinux,
		},
		guest: &guestSSH{cfg: GuestSSHConfig{Platform: platformLinux, Host: "127.0.0.1", Port: 2223, User: "penguinbox"}},
		logf:  func(logging.Class, string, ...any) {},
	}
	e.roots = e.sourceRoots()
	if _, err := e.roots.pick("c_agent"); err != nil {
		t.Fatalf("c_agent root: %v", err)
	}
	editor := map[string]bool{}
	for _, candidate := range e.toolsFor(roleEditor) {
		editor[candidate.Name()] = true
	}
	if !editor["BuildShellcode"] {
		t.Fatal("Linux editor must be able to run the malasada producer")
	}
	debugger := map[string]bool{}
	for _, candidate := range e.toolsFor(roleDebugger) {
		debugger[candidate.Name()] = true
	}
	if debugger["RunModule"] {
		t.Fatalf("Linux debugger registered the Windows module runner: %v", debugger)
	}
	if !debugger["GuestSSH"] {
		t.Fatalf("Linux debugger did not register GuestSSH: %v", debugger)
	}
}

func TestLinuxDebuggerAvailableWithGuest(t *testing.T) {
	e := &evolver{
		cfg: EvolveConfig{
			Platform: platformLinux, DebuggerPolicy: debuggerPolicyCycle, Iterations: 2,
		},
		guest: &guestSSH{cfg: GuestSSHConfig{Platform: platformLinux, Host: "127.0.0.1", Port: 2223, User: "penguinbox"}},
		logf:  func(logging.Class, string, ...any) {},
	}
	c := newCoordinator(e, nil, "scripted", nil, "")
	if !c.debuggerAvailableFor(&Cycle{ID: 1}) {
		t.Fatal("Linux debugger was not available with a configured guest and cycle policy")
	}
}
