package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/opsec"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func TestScreenFailsClosedWhenAuditIsUnavailable(t *testing.T) {
	audit, err := OpenAudit(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	_ = audit.Close()
	actions := &Actions{Policy: opsec.DefaultPolicy(), Audit: audit}
	decision, err := actions.screen("test", "", "whoami", nil, def.OpsecReview{Noise: "low", Reversible: true})
	if err == nil {
		t.Fatal("expected the audit write to fail")
	}
	if decision.Allowed {
		t.Fatalf("action allowed without an audit record: %+v", decision)
	}
}

func TestUploadFileDefaultsToMemfs(t *testing.T) {
	target := &def.Emp3r0rAgent{Tag: "target-1", GOOS: "linux", AgentImpl: "go"}
	exec := &recordingExecutor{}
	actions := &Actions{
		Target:   func() *def.Emp3r0rAgent { return target },
		Policy:   opsec.DefaultPolicy(),
		Executor: exec,
	}
	out, err := actions.uploadFile(context.Background(), json.RawMessage(`{"src":"/tmp/payload.bin"}`))
	if err != nil {
		t.Fatal(err)
	}
	result := out.(map[string]any)
	if result["executed"] != true || result["blocked"] == true {
		t.Fatalf("memfs upload was not executed: %v", result)
	}
	if result["dst"] != "memfs:///payload.bin" || result["memfs"] != true {
		t.Fatalf("default destination = %v, want memfs:///payload.bin", result["dst"])
	}
	if len(exec.uploads) != 1 || exec.uploads[0] != "/tmp/payload.bin -> memfs:///payload.bin" {
		t.Fatalf("upload calls = %v", exec.uploads)
	}
	warnings, _ := result["warnings"].([]string)
	if len(warnings) == 0 {
		t.Fatalf("data transfer had no warning: %v", result)
	}
}

func TestUploadFileRejectsProtectedSource(t *testing.T) {
	target := &def.Emp3r0rAgent{Tag: "target-1", GOOS: "linux", AgentImpl: "go"}
	exec := &recordingExecutor{}
	actions := &Actions{
		Target:   func() *def.Emp3r0rAgent { return target },
		Policy:   opsec.DefaultPolicy(),
		Executor: exec,
	}
	for _, src := range []string{"/home/operator/.ssh/id_rsa", "/home/operator/.emp3r0r/magic_string", "/home/operator/.emp3r0r/emp3r0r.history", "/home/operator/.emp3r0r/operator.key"} {
		if _, err := actions.uploadFile(context.Background(), json.RawMessage(`{"src":`+strconv.Quote(src)+`}`)); err == nil {
			t.Fatalf("%s was accepted", src)
		}
	}
	if len(exec.uploads) != 0 {
		t.Fatalf("protected source reached the target: %v", exec.uploads)
	}
}

func TestUploadFileWarnsForDiskDestinationByDefault(t *testing.T) {
	target := &def.Emp3r0rAgent{Tag: "target-1", GOOS: "linux", AgentImpl: "go"}
	exec := &recordingExecutor{}
	actions := &Actions{
		Target:   func() *def.Emp3r0rAgent { return target },
		Policy:   opsec.DefaultPolicy(),
		Executor: exec,
	}
	out, err := actions.uploadFile(context.Background(), json.RawMessage(`{"src":"/tmp/payload.bin","dst":"/tmp/payload.bin"}`))
	if err != nil {
		t.Fatal(err)
	}
	result := out.(map[string]any)
	if result["executed"] != true || result["blocked"] == true {
		t.Fatalf("disk upload was not executed with a warning: %v", result)
	}
	if result["memfs"] != false {
		t.Fatalf("disk upload reported memfs: %v", result)
	}
	warnings, _ := result["warnings"].([]string)
	if len(warnings) == 0 {
		t.Fatalf("disk upload had no filesystem-artifact warning: %v", result)
	}
	if len(exec.uploads) != 1 {
		t.Fatalf("upload calls = %v", exec.uploads)
	}
}

func TestUploadFileAllowsDiskWithFilesystemGate(t *testing.T) {
	target := &def.Emp3r0rAgent{Tag: "target-1", GOOS: "linux", AgentImpl: "go"}
	exec := &recordingExecutor{}
	policy := opsec.DefaultPolicy()
	policy.Capabilities["filesystem-artifact"] = opsec.ModeAllow
	actions := &Actions{
		Target:   func() *def.Emp3r0rAgent { return target },
		Policy:   policy,
		Executor: exec,
	}
	out, err := actions.uploadFile(context.Background(), json.RawMessage(`{"src":"/tmp/payload.bin","dst":"/tmp/payload.bin"}`))
	if err != nil {
		t.Fatal(err)
	}
	result := out.(map[string]any)
	if result["executed"] != true || result["memfs"] != false {
		t.Fatalf("gated disk upload was not executed: %v", result)
	}
}

func TestDownloadFileReportsLocalPath(t *testing.T) {
	target := &def.Emp3r0rAgent{Tag: "target-1", GOOS: "linux", AgentImpl: "go"}
	exec := &recordingExecutor{}
	actions := &Actions{
		Target:   func() *def.Emp3r0rAgent { return target },
		Policy:   opsec.DefaultPolicy(),
		Executor: exec,
	}
	out, err := actions.downloadFile(context.Background(), json.RawMessage(`{"path":"/var/log/auth.log"}`))
	if err != nil {
		t.Fatal(err)
	}
	result := out.(map[string]any)
	if result["executed"] != true || result["local_path"] != "/downloads/auth.log" {
		t.Fatalf("download result = %v", result)
	}
	if len(exec.downloads) != 1 || exec.downloads[0] != "/var/log/auth.log" {
		t.Fatalf("download calls = %v", exec.downloads)
	}
	warnings, _ := result["warnings"].([]string)
	if len(warnings) == 0 {
		t.Fatalf("download had no data-transfer warning: %v", result)
	}
}

func TestDownloadFileRejectsControlCharacters(t *testing.T) {
	actions := &Actions{Policy: opsec.DefaultPolicy(), Executor: &recordingExecutor{}}
	if _, err := actions.downloadFile(context.Background(), json.RawMessage(`{"path":"/tmp/a\nb"}`)); err == nil {
		t.Fatal("path with a newline was accepted")
	}
}

func TestBuiltinLsRendersAndDispatches(t *testing.T) {
	target := &def.Emp3r0rAgent{Tag: "target-1", GOOS: "linux", AgentImpl: "go"}
	exec := &recordingExecutor{}
	actions := &Actions{
		Target:   func() *def.Emp3r0rAgent { return target },
		Policy:   opsec.DefaultPolicy(),
		Executor: exec,
	}
	out, err := actions.ls(context.Background(), json.RawMessage(`{"path":"/tmp"}`))
	if err != nil {
		t.Fatal(err)
	}
	result := out.(map[string]any)
	if result["executed"] != true || result["job_id"] != "job-builtin" {
		t.Fatalf("result = %v", result)
	}
	if len(exec.builtins) != 1 || exec.builtins[0] != `ls --dst "/tmp"` {
		t.Fatalf("executor = %v", exec.builtins)
	}
}

func TestBuiltinRmScreensAsDestructive(t *testing.T) {
	target := &def.Emp3r0rAgent{Tag: "target-1", GOOS: "linux", AgentImpl: "go"}
	exec := &recordingExecutor{}
	policy := opsec.DefaultPolicy()
	policy.Capabilities["destructive"] = opsec.ModeBlock
	actions := &Actions{
		Target:   func() *def.Emp3r0rAgent { return target },
		Policy:   policy,
		Executor: exec,
	}
	out, err := actions.rm(context.Background(), json.RawMessage(`{"path":"/tmp/x"}`))
	if err != nil {
		t.Fatal(err)
	}
	result := out.(map[string]any)
	if result["blocked"] != true || result["executed"] != false {
		t.Fatalf("rm was not blocked: %v", result)
	}
	if len(exec.builtins) != 0 {
		t.Fatalf("blocked rm reached the target: %v", exec.builtins)
	}
}

func TestBuiltinRejectsControlCharacters(t *testing.T) {
	target := &def.Emp3r0rAgent{Tag: "target-1", GOOS: "linux", AgentImpl: "go"}
	actions := &Actions{
		Target:   func() *def.Emp3r0rAgent { return target },
		Policy:   opsec.DefaultPolicy(),
		Executor: &recordingExecutor{},
	}
	if _, err := actions.cat(context.Background(), json.RawMessage(`{"path":"/tmp/a\nb"}`)); err == nil {
		t.Fatal("path with a newline was accepted")
	}
}

func TestBuiltinRejectsCAgent(t *testing.T) {
	target := &def.Emp3r0rAgent{Tag: "target-1", GOOS: "linux", AgentImpl: "c"}
	actions := &Actions{
		Target:   func() *def.Emp3r0rAgent { return target },
		Policy:   opsec.DefaultPolicy(),
		Executor: &recordingExecutor{},
	}
	if _, err := actions.ls(context.Background(), json.RawMessage(`{}`)); err == nil {
		t.Fatal("C agent accepted a built-in command tool")
	}
}

func TestForgetAgentRequiresIrreversiblePolicy(t *testing.T) {
	target := &def.Emp3r0rAgent{Tag: "target-1", GOOS: "linux", AgentImpl: "go"}
	exec := &recordingExecutor{}
	policy := opsec.DefaultPolicy()
	policy.AllowIrreversible = false
	actions := &Actions{
		Target:   func() *def.Emp3r0rAgent { return target },
		Policy:   policy,
		Executor: exec,
	}
	out, err := actions.forgetAgent(context.Background(), json.RawMessage(`{"agent":"target-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	result := out.(map[string]any)
	if result["blocked"] != true || result["executed"] != false {
		t.Fatalf("forget_agent was not blocked: %v", result)
	}
	if len(exec.forgot) != 0 {
		t.Fatalf("blocked forget reached the executor: %v", exec.forgot)
	}

	actions.Policy.AllowIrreversible = true
	out, err = actions.forgetAgent(context.Background(), json.RawMessage(`{"agent":"target-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if out.(map[string]any)["executed"] != true || len(exec.forgot) != 1 {
		t.Fatalf("forget_agent did not execute: %v", out)
	}
}

func TestSocksStartDispatchesThroughExecutor(t *testing.T) {
	target := &def.Emp3r0rAgent{Tag: "target-1", GOOS: "linux", AgentImpl: "go"}
	actions := &Actions{
		Target:   func() *def.Emp3r0rAgent { return target },
		Policy:   opsec.DefaultPolicy(),
		Executor: &recordingExecutor{},
	}
	out, err := actions.socksStart(context.Background(), json.RawMessage(`{"port":1080}`))
	if err != nil {
		t.Fatal(err)
	}
	result := out.(map[string]any)
	if result["executed"] != true || result["port"] != float64(1080) && result["port"] != 1080 {
		t.Fatalf("socks_start result = %v", result)
	}
	if result["agent"] != "target-1" {
		t.Fatalf("agent = %v", result["agent"])
	}
}

func TestTun2SocksStartRequiresRoute(t *testing.T) {
	actions := &Actions{Policy: opsec.DefaultPolicy(), Executor: &recordingExecutor{}}
	if _, err := actions.tun2socksStart(context.Background(), json.RawMessage(`{}`)); err == nil {
		t.Fatal("missing route was accepted")
	}
	if _, err := actions.tun2socksStart(context.Background(), json.RawMessage(`{"route":["not-a-prefix"]}`)); err == nil {
		t.Fatal("invalid route was accepted")
	}
}

func TestSuicideScreensAsDestructive(t *testing.T) {
	target := &def.Emp3r0rAgent{Tag: "target-1", GOOS: "linux", AgentImpl: "go"}
	exec := &recordingExecutor{}
	policy := opsec.DefaultPolicy()
	policy.Capabilities["destructive"] = opsec.ModeBlock
	actions := &Actions{
		Target:   func() *def.Emp3r0rAgent { return target },
		Policy:   policy,
		Executor: exec,
	}
	out, err := actions.suicide(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	result := out.(map[string]any)
	if result["blocked"] != true || len(exec.builtins) != 0 {
		t.Fatalf("suicide was not blocked: %v", result)
	}
}
