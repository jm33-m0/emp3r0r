package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func TestParseGeneratedPayloads(t *testing.T) {
	log := strings.Join([]string{
		"building stager",
		"[+] generated payload: /tmp/work/stager.bin (4096 bytes)",
		"[+] generated payload: C:\\out\\loader.exe (1024 bytes)\r",
		"[+] generated payload: broken line",
		"[+] generated payload: /tmp/zero.bin (0 bytes)",
	}, "\n")
	got := ParseGeneratedPayloads(log)
	if len(got) != 2 {
		t.Fatalf("payloads = %d, want 2: %+v", len(got), got)
	}
	if got[0].Path != "/tmp/work/stager.bin" || got[0].Size != 4096 {
		t.Fatalf("first = %+v", got[0])
	}
	if got[1].Path != `C:\out\loader.exe` || got[1].Size != 1024 {
		t.Fatalf("second = %+v", got[1])
	}
}

func TestBuildPlanSeparatesPassiveAndActiveStages(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "loader.exe")
	if err := os.WriteFile(artifact, []byte("MZ\x90\x00payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bootstrap.c"), []byte("void run(void) {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	health := Health{
		URL:         "http://127.0.0.1:1337",
		Available:   true,
		Scanners:    []Scanner{{Group: "static", Name: "yara", Status: "ok", Enabled: true, Exists: true}, {Group: "dynamic", Name: "pe_sieve", Status: "ok", Enabled: true, Exists: true}},
		EDRProfiles: []string{"elastic"},
	}
	plan, err := BuildPlan(Request{Module: "loader_windows", ModuleDir: dir, Platform: "Windows", ArtifactPath: artifact}, health)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Artifact.Kind != "pe" || plan.Platform != "windows" {
		t.Fatalf("artifact = %+v platform = %s", plan.Artifact, plan.Platform)
	}
	var static, dynamic, edr int
	for _, stage := range plan.Stages {
		switch stage.Kind {
		case StageStatic:
			static++
			if stage.Executes || stage.RequiresApproval || !stage.Runnable {
				t.Fatalf("static stage = %+v", stage)
			}
		case StageDynamic:
			dynamic++
			if !stage.Executes || !stage.RequiresApproval || !stage.Runnable {
				t.Fatalf("dynamic stage = %+v", stage)
			}
		case StageEDR:
			edr++
			if !stage.Executes || !stage.RequiresApproval || !stage.Runnable {
				t.Fatalf("EDR stage = %+v", stage)
			}
		}
	}
	if static != 1 || dynamic != 1 || edr != 1 {
		t.Fatalf("stages static=%d dynamic=%d edr=%d", static, dynamic, edr)
	}
	if len(plan.SourceTargets) == 0 {
		t.Fatal("no source targets listed")
	}
}

func TestBuildPlanLinuxSkipsDetonation(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "stager.bin")
	if err := os.WriteFile(artifact, []byte("\x7fELFpayload"), 0o600); err != nil {
		t.Fatal(err)
	}
	health := Health{
		Available: true,
		Scanners:  []Scanner{{Group: "static", Name: "yara", Status: "ok", Enabled: true, Exists: true}, {Group: "dynamic", Name: "pe_sieve", Status: "ok", Enabled: true, Exists: true}},
	}
	plan, err := BuildPlan(Request{Module: "stager_linux", ModuleDir: dir, Platform: "Linux", ArtifactPath: artifact}, health)
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range plan.Stages {
		if stage.Kind == StageDynamic && stage.Runnable {
			t.Fatalf("dynamic stage must not run a Linux artifact: %+v", stage)
		}
	}
}

func TestBuildFeedbackMapsIndicatorsToSource(t *testing.T) {
	dir := t.TempDir()
	source := "void run(void) {\n  void *p = VirtualAllocEx(h, 0, size, 0, 0);\n  char *s = \"secret-marker\";\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "bootstrap.c"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := json.RawMessage(`{
	  "yara": {"matches": [{"rule": "C2_Beacon", "meta": {"severity": "HIGH"},
	    "strings": [{"identifier": "$a", "data": "VirtualAllocEx"}]}]},
	  "stringnalyzer": {"findings": {"found_suspicious_strings": ["secret-marker"],
	    "found_ip": ["203.0.113.9"]}}
	}`)
	run := Run{
		ID:     "loader_windows-abc",
		Module: "loader_windows",
		Plan:   Plan{Module: "loader_windows", ModuleDir: dir, Artifact: Artifact{Name: "loader.exe"}},
		Stages: []StageResult{{Kind: StageStatic, Tool: "yara", Status: "completed", Raw: raw}},
	}
	feedback := BuildFeedback(run)
	if len(feedback.Findings) < 2 {
		t.Fatalf("findings = %d: %+v", len(feedback.Findings), feedback.Findings)
	}
	var foundAPI, foundString bool
	for _, finding := range feedback.Findings {
		for _, location := range finding.Sources {
			if location.File != "bootstrap.c" {
				t.Fatalf("location = %+v", location)
			}
			switch finding.Indicator {
			case "VirtualAllocEx":
				foundAPI = true
				if location.Line != 2 {
					t.Fatalf("VirtualAllocEx line = %d", location.Line)
				}
			case "secret-marker":
				foundString = true
				if location.Line != 3 {
					t.Fatalf("secret-marker line = %d", location.Line)
				}
			}
		}
	}
	if !foundAPI || !foundString {
		t.Fatalf("API=%v string=%v findings=%+v", foundAPI, foundString, feedback.Findings)
	}
	if len(feedback.SourceEdits) == 0 {
		t.Fatal("no source edits")
	}
}

func TestRunPlanSkipsExecutionWithoutApproval(t *testing.T) {
	var dynamicCalls atomic.Int32
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
			fmt.Fprint(w, `{"file_info": {"md5": "d41d8cd98f00b204e9800998ecf8427e", "sha256": "abc", "size": 10, "original_name": "loader.exe"}}`)
		case strings.HasPrefix(r.URL.Path, "/analyze/static/"):
			fmt.Fprint(w, `{"status": "success", "results": {"yara": {"matches": [], "status": "completed"}}}`)
		case strings.HasPrefix(r.URL.Path, "/analyze/dynamic/"):
			dynamicCalls.Add(1)
			fmt.Fprint(w, `{"status": "success"}`)
		case strings.HasPrefix(r.URL.Path, "/api/results/dynamic/"):
			fmt.Fprint(w, `{"status": "completed", "scanners": {}}`)
		case strings.HasPrefix(r.URL.Path, "/api/results/risk/"):
			fmt.Fprint(w, `{"risk_score": 0, "risk_level": "Low"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	loop, err := NewLoop(LoopConfig{SandboxURL: server.URL, StoreRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	artifact := filepath.Join(dir, "loader.exe")
	if err := os.WriteFile(artifact, []byte("MZpayload"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := loop.CreatePlan(context.Background(), Request{Module: "loader_windows", ModuleDir: dir, Platform: "windows", ArtifactPath: artifact})
	if err != nil {
		t.Fatal(err)
	}

	run, err := loop.RunPlan(context.Background(), plan, RunOptions{Static: true, Dynamic: true})
	if err != nil {
		t.Fatal(err)
	}
	if dynamicCalls.Load() != 0 {
		t.Fatalf("dynamic ran without approval: %d calls", dynamicCalls.Load())
	}
	var skipped bool
	for _, stage := range run.Stages {
		if stage.Kind == StageDynamic && stage.Status == "skipped" && strings.Contains(stage.Reason, "approve_execution") {
			skipped = true
		}
	}
	if !skipped {
		t.Fatalf("dynamic stage was not skipped: %+v", run.Stages)
	}

	run, err = loop.RunPlan(context.Background(), plan, RunOptions{Static: true, Dynamic: true, ApproveExecution: true})
	if err != nil {
		t.Fatal(err)
	}
	if dynamicCalls.Load() != 1 {
		t.Fatalf("dynamic calls = %d, want 1", dynamicCalls.Load())
	}
	if !run.Executed {
		t.Fatal("run did not record execution")
	}
	if _, err := loop.Store.Load(run.ID); err != nil {
		t.Fatalf("load run: %v", err)
	}
}

func TestStoreRecordsArtifactsAndRuns(t *testing.T) {
	store := NewStore(t.TempDir())
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "stager.bin")
	if err := os.WriteFile(artifactPath, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := InspectArtifact(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordArtifact("stager_linux", artifact); err != nil {
		t.Fatal(err)
	}
	known, ok := store.KnownArtifact("stager_linux", artifactPath)
	if !ok || known.SHA256 != artifact.SHA256 {
		t.Fatalf("known = %+v ok=%v", known, ok)
	}
	if _, ok := store.KnownArtifact("stager_linux", filepath.Join(dir, "other.bin")); ok {
		t.Fatal("unrecorded artifact accepted")
	}
	run := Run{Module: "stager_linux", Plan: Plan{Module: "stager_linux", Artifact: artifact}}
	saved, err := store.Save(run)
	if err != nil {
		t.Fatal(err)
	}
	latest, ok, err := store.Latest("stager_linux")
	if err != nil || !ok {
		t.Fatalf("latest ok=%v err=%v", ok, err)
	}
	if latest.ID != saved.ID {
		t.Fatalf("latest = %s want %s", latest.ID, saved.ID)
	}
	runs, err := store.List()
	if err != nil || len(runs) != 1 {
		t.Fatalf("runs = %d err=%v", len(runs), err)
	}
}

func TestAnalystPathStaysInsideModuleDir(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "build.sh"), []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := analystPath(root, "../secret.c"); err == nil {
		t.Fatal("escaping path accepted")
	}
	if _, err := analystPath(root, "build.sh"); err != nil {
		t.Fatalf("valid path rejected: %v", err)
	}
}

type scriptedProvider struct{ answer string }

func (p scriptedProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		if !yield(llm.StreamEvent{Type: llm.SEMessageStart}, nil) {
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: p.answer}, nil) {
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil) {
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func (p scriptedProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(p.answer)}}, "end_turn", llm.Usage{}, nil
}

func TestAnalystParsesEditProposals(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bootstrap.c"), []byte("void run(void) {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	analyst, err := NewAnalyst(AnalystConfig{Provider: scriptedProvider{answer: `{"summary":"replace the literal","edits":[{"file":"bootstrap.c","line":1,"reason":"scanner hit","change":"derive the name at runtime"}]}`}, WorkingDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	answer, err := analyst.Analyze(context.Background(), Feedback{RunID: "run-1", Module: "loader_windows", ModuleDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Summary string `json:"summary"`
		Edits   []struct {
			File string `json:"file"`
		} `json:"edits"`
	}
	if err := json.Unmarshal(answer, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Summary != "replace the literal" || len(parsed.Edits) != 1 || parsed.Edits[0].File != "bootstrap.c" {
		t.Fatalf("answer = %+v", parsed)
	}
}

func TestAnalystToolsAreReadOnlyAndScoped(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "bootstrap.c"), []byte("line one\nVirtualAllocEx(h, 0, 0, 0, 0);\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	list := analystListTool(root)
	if !list.IsReadOnly(nil) {
		t.Fatal("SourceList is not read-only")
	}
	result, err := list.Call(context.Background(), json.RawMessage(`{}`), nil)
	if err != nil || !strings.Contains(result.Flatten(), "bootstrap.c") {
		t.Fatalf("list = %q err=%v", result.Flatten(), err)
	}
	read := analystReadTool(root)
	result, err = read.Call(context.Background(), json.RawMessage(`{"path":"bootstrap.c","start_line":2,"end_line":2}`), nil)
	if err != nil || !strings.Contains(result.Flatten(), "VirtualAllocEx") {
		t.Fatalf("read = %q err=%v", result.Flatten(), err)
	}
	result, err = read.Call(context.Background(), json.RawMessage(`{"path":"../secret.c"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatalf("escaping read succeeded: %q", result.Flatten())
	}
	search := analystSearchTool(root)
	result, err = search.Call(context.Background(), json.RawMessage(`{"pattern":"VirtualAlloc"}`), nil)
	if err != nil || !strings.Contains(result.Flatten(), "bootstrap.c:2") {
		t.Fatalf("search = %q err=%v", result.Flatten(), err)
	}
}
