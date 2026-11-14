package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/modconfig"
)

func TestIsSystemImageTreatsBareModuleNamesAsSystem(t *testing.T) {
	for _, name := range []string{"KERNEL32.DLL", "kernelbase.dll", "ntdll.dll"} {
		if !isSystemImage(name) {
			t.Fatalf("%s should be a system image", name)
		}
	}
	if isSystemImage(`C:\LitterBox\Uploads\agent.exe`) {
		t.Fatal("user-writable image treated as system")
	}
	if !isSystemImage(`C:\Windows\System32\kernel32.dll`) {
		t.Fatal("system path not treated as system")
	}
}

func TestHasActionableFindingsIgnoresUnmatchedMediums(t *testing.T) {
	unmatched := []Finding{
		{Stage: StageTelemetry, Severity: "medium", Rule: "telemetry/user-module"},
		{Stage: StageDynamic, Severity: "medium", Tool: "hollows_hunter"},
	}
	if hasActionableFindings(unmatched) {
		t.Fatal("unmatched medium findings must be residuals")
	}
	matched := []Finding{{
		Stage: StageTelemetry, Severity: "medium", Rule: "telemetry/cross-process-write",
		Sources: []SourceLocation{{File: "loader.c", Line: 10}},
	}}
	if !hasActionableFindings(matched) {
		t.Fatal("medium finding with a source location is actionable")
	}
	if !hasActionableFindings([]Finding{{Stage: StageTelemetry, Severity: "high"}}) {
		t.Fatal("high finding is always actionable")
	}
}

func TestGuardModuleConfigKeepsDocumentedSurface(t *testing.T) {
	before := `[{"name":"donut","build":"bash ./build.sh","parameters":[
		{"name":"input"},{"name":"inject","choices":["apc","ct"]}]}]`
	cases := []struct {
		name  string
		after string
		ok    bool
	}{
		{
			name: "adds an option",
			after: `[{"name":"donut","build":"bash ./build.sh","parameters":[
				{"name":"input"},{"name":"inject","choices":["apc","ct"]},{"name":"decoy"}]}]`,
			ok: true,
		},
		{
			name: "changes a default only",
			after: `[{"name":"donut","build":"bash ./build.sh","parameters":[
				{"name":"input"},{"name":"inject","choices":["apc","ct"],"default":"ct"}]}]`,
			ok: true,
		},
		{
			name: "removes a choice",
			after: `[{"name":"donut","build":"bash ./build.sh","parameters":[
				{"name":"input"},{"name":"inject","choices":["apc"]}]}]`,
		},
		{
			name: "removes an option",
			after: `[{"name":"donut","build":"bash ./build.sh","parameters":[
				{"name":"input"}]}]`,
		},
		{
			name: "renames the module",
			after: `[{"name":"generator","build":"bash ./build.sh","parameters":[
				{"name":"input"}]}]`,
		},
		{
			name: "changes the build entrypoint",
			after: `[{"name":"donut","build":"bash ./other.sh","parameters":[
				{"name":"input"},{"name":"inject","choices":["apc","ct"]}]}]`,
		},
		{
			name:  "invalid json",
			after: `[`,
		},
	}
	for _, tc := range cases {
		err := guardModuleConfig(before, tc.after)
		if tc.ok && err != nil {
			t.Fatalf("%s: unexpected error %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%s: expected a rejection", tc.name)
		}
	}
}

func TestSourceRootsKeepEditsInsideWritableRoots(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirA, "a.c"), []byte("int a;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := newSourceRoots("payload", sourceRoot{Name: "payload", Dir: dirA, Writable: true}, sourceRoot{Name: "deps", Dir: dirB})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := roots.resolve("", "a.c"); err != nil {
		t.Fatalf("payload read: %v", err)
	}
	if _, _, err := roots.resolve("deps", "../../etc/passwd"); err == nil {
		t.Fatal("escaped path was accepted")
	}
	dep, err := roots.pick("deps")
	if err != nil || dep.Writable {
		t.Fatalf("deps root = %+v err=%v", dep, err)
	}
	if _, err := roots.pick("missing"); err == nil {
		t.Fatal("unknown root was accepted")
	}
}

func TestValidateProducerOptionsRejectsUnknownAndInternal(t *testing.T) {
	declared := def.ModOptions{
		"input":    {Name: "input", Required: true},
		"arch":     {Name: "arch", Vals: []string{"1", "2", "3"}},
		"internal": {Name: "internal", Internal: true},
	}
	if flags, err := validateProducerOptions("donut", declared, map[string]string{"input": "agent.exe", "arch": "2"}, "input"); err != nil || flags["arch"] != "2" {
		t.Fatalf("valid options rejected: %v %+v", err, flags)
	}
	for name, tc := range map[string]struct {
		supplied map[string]string
		deferred string
	}{
		"unknown":  {supplied: map[string]string{"input": "agent.exe", "nope": "1"}, deferred: "input"},
		"internal": {supplied: map[string]string{"input": "agent.exe", "internal": "1"}, deferred: "input"},
		"choice":   {supplied: map[string]string{"input": "agent.exe", "arch": "9"}, deferred: "input"},
		"required": {supplied: map[string]string{"arch": "2"}},
	} {
		if _, err := validateProducerOptions("donut", declared, tc.supplied, tc.deferred); err == nil {
			t.Fatalf("%s: expected rejection", name)
		}
	}
}

func TestFTSTermsNeutraliseOperators(t *testing.T) {
	terms := ftsTerms(`module stomping" OR * NEAR("etc") --`)
	joined := strings.Join(terms, ",")
	for _, forbidden := range []string{`"`, `*`, "OR", "NEAR", "--"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("term %q survived sanitising: %q", forbidden, joined)
		}
	}
	if len(terms) != 5 {
		t.Fatalf("terms = %v", terms)
	}
}

func TestKnowledgeSyncCachesAndSearchesOffline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     int             `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		var result any
		switch request.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": "2025-03-26"}
		case "tools/call":
			var call struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			if err := json.Unmarshal(request.Params, &call); err != nil {
				t.Errorf("decode call: %v", err)
				return
			}
			switch call.Name {
			case "list_bookmarks":
				result = mcpText(t, knowledgeCatalog{
					Notebooks: []string{"maldev"},
					Bookmarks: []knowledgeBookmark{
						{Notebook: "maldev", Filename: "stomp.llm", Title: "Stomping", Summarized: true, URL: "https://example/stomp"},
						{Notebook: "maldev", Filename: "raw.md", Title: "Not summarised"},
					},
				})
			case "get_documents":
				var args struct {
					DocumentRefs []string `json:"document_refs"`
					Artifact     string   `json:"artifact"`
				}
				if err := json.Unmarshal(call.Arguments, &args); err != nil {
					t.Errorf("decode arguments: %v", err)
					return
				}
				var docs []knowledgeDocument
				for _, ref := range args.DocumentRefs {
					docs = append(docs, knowledgeDocument{
						DocumentRef: ref, Artifact: args.Artifact,
						Content: "Module stomping maps payload bytes over a legitimate module .text.",
					})
				}
				result = mcpText(t, knowledgeDocuments{Documents: docs})
			default:
				t.Errorf("unexpected tool %q", call.Name)
			}
		default:
			t.Errorf("unexpected method %q", request.Method)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
		_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", payload)
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "knowledge.db")
	db, err := OpenKnowledgeDB(path, true)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := SyncKnowledge(context.Background(), db, KnowledgeSyncOptions{URL: server.URL})
	_ = db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Summaries != 1 || stats.Skipped != 1 {
		t.Fatalf("stats = %+v", stats)
	}

	readOnly, err := OpenKnowledgeDB(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = readOnly.Close() }()
	hits, err := readOnly.Search(context.Background(), "module stomping", "", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].DocRef != "maldev/stomp" {
		t.Fatalf("hits = %+v", hits)
	}
	doc, err := readOnly.Read(context.Background(), hits[0].DocRef, "summary", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(doc.Content, "legitimate module") || doc.Artifact != "summary" {
		t.Fatalf("document = %+v", doc)
	}
}

func mcpText(t *testing.T, value any) mcpToolResult {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return mcpToolResult{Content: []mcpContent{{Type: "text", Text: string(encoded)}}}
}

func TestBuildShellcodeRunsProducerAndSwapsShellcode(t *testing.T) {
	producerDir := t.TempDir()
	config := `[{"name":"donut","build":"bash ./build.sh","is_local":true,"parameters":[
		{"name":"input","type":"string","required":true},
		{"name":"output","type":"string"},
		{"name":"arch","type":"string","choices":["1","2","3"]}]}]`
	if err := os.WriteFile(filepath.Join(producerDir, "config.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	payloadDir := t.TempDir()
	seedExe := filepath.Join(payloadDir, "agent.exe")
	if err := os.WriteFile(seedExe, []byte("MZagent"), 0o600); err != nil {
		t.Fatal(err)
	}
	shellcode := filepath.Join(payloadDir, "agent.exe.bin")
	if err := os.WriteFile(shellcode, []byte("seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	moduleDir := t.TempDir()
	e := &evolver{
		cfg: EvolveConfig{
			LoopID: "loop-test", Module: "loader_windows", ModuleDir: moduleDir,
			Shellcode: shellcode, StoreRoot: t.TempDir(),
			ProducerDirs: map[string]string{"donut": producerDir},
			BuildProducer: func(_ string, module string, flags map[string]string) (string, error) {
				if module != "donut" {
					return "", fmt.Errorf("unexpected module %q", module)
				}
				out := flags["output"]
				body := "SHELL:" + flags["input"]
				if err := os.WriteFile(out, []byte(body), 0o600); err != nil {
					return "", err
				}
				return fmt.Sprintf("[+] generated payload: %s (%d bytes)\n", out, len(body)), nil
			},
		},
		logf: func(logging.Class, string, ...any) {},
	}
	e.roots = e.sourceRoots()
	tool := e.buildShellcodeTool()

	result, err := tool.Call(context.Background(), json.RawMessage(`{"producer":"donut","options":{"arch":"2"}}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("tool error: %+v", result)
	}
	if e.shellcode == shellcode || !strings.HasPrefix(e.shellcode, e.cfg.StoreRoot) {
		t.Fatalf("shellcode was not swapped: %s", e.shellcode)
	}
	data, err := os.ReadFile(e.shellcode)
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(seedExe)
	if !strings.Contains(string(data), "SHELL:"+abs) {
		t.Fatalf("producer input not used: %q", data)
	}
	bad, err := tool.Call(context.Background(), json.RawMessage(`{"producer":"donut","options":{"arch":"9"}}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bad.IsError {
		t.Fatal("invalid choice was accepted")
	}
	escape, err := tool.Call(context.Background(), json.RawMessage(`{"producer":"donut","options":{"input":"/etc/passwd"}}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !escape.IsError {
		t.Fatal("input outside the payload directory was accepted")
	}
}

func TestCoverageRecordsAnalyzerFailures(t *testing.T) {
	events := []telemetryEvent{
		{Category: "analysis", Event: "dynamic/yara", Attrs: `{"errors":"error scanning 5412: error: 47","matches":[]}`},
		{Category: "analysis", Event: "dynamic/hsb", Attrs: `{"findings":{}}`},
		{Category: "analysis", Event: "dynamic/analysis_metadata", Attrs: `{"analysis_started":false,"early_termination":true}`},
	}
	coverage := buildTelemetryCoverage(events, nil)
	if !strings.HasPrefix(coverage.Analyzers["dynamic/yara"], "failed:") {
		t.Fatalf("yara status = %q", coverage.Analyzers["dynamic/yara"])
	}
	if coverage.Analyzers["dynamic/hsb"] != "ok" {
		t.Fatalf("hsb status = %q", coverage.Analyzers["dynamic/hsb"])
	}
	if coverage.Analyzers["dynamic/analysis_metadata"] != "early termination" {
		t.Fatalf("metadata status = %q", coverage.Analyzers["dynamic/analysis_metadata"])
	}
	missing := strings.Join(coverage.Missing, ";")
	if !strings.Contains(missing, "dynamic/yara") || !strings.Contains(missing, "early termination") {
		t.Fatalf("missing = %v", coverage.Missing)
	}
}

func TestParseGenericDropsTimelinePseudoFindings(t *testing.T) {
	raw := json.RawMessage(`{"detections":[{"severity":"MID","findings":[
		{"description":"Callstack contains private memory regions","details":{}},
		{"description":"Elevated unbacked execute","details":{}}],
		"timeline":[{"details":"Loaded image: KERNEL32.DLL"},{"details":"Process started: PID 42"}]}]}`)
	findings := parseGeneric(raw, StageDynamic)
	var indicators []string
	for _, finding := range findings {
		indicators = append(indicators, finding.Indicator)
	}
	joined := strings.Join(indicators, " | ")
	if !strings.Contains(joined, "Callstack contains private memory regions") {
		t.Fatalf("real detection dropped: %v", indicators)
	}
	if strings.Contains(joined, "Loaded image") || strings.Contains(joined, "Process started") {
		t.Fatalf("timeline noise kept: %v", indicators)
	}
}

func TestNormalizeEvolveConfigHonoursOperatorBudget(t *testing.T) {
	moduleDir := t.TempDir()
	shellcode := filepath.Join(t.TempDir(), "agent.bin")
	if err := os.WriteFile(shellcode, []byte("shellcode"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := EvolveConfig{
		Module: "loader_windows", ModuleDir: moduleDir, Shellcode: shellcode,
		StoreRoot: t.TempDir(), Stages: []string{"dynamic"},
		Iterations: 12, Turns: 200,
	}
	if err := normalizeEvolveConfig(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Iterations != 12 || cfg.Turns != 200 {
		t.Fatalf("operator budget changed: iterations=%d turns=%d", cfg.Iterations, cfg.Turns)
	}
}

func TestDonutProducerModuleContract(t *testing.T) {
	moduleDir := filepath.Join("..", "..", "..", "modules", "donut")
	configs, err := modconfig.ReadConfigs(filepath.Join(moduleDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var donut *def.ModuleConfig
	for _, cfg := range configs {
		if cfg != nil && cfg.Name == "donut" {
			donut = cfg
			break
		}
	}
	if donut == nil || !donut.IsLocal || donut.Build != "bash ./build.sh" {
		t.Fatalf("donut module = %+v", donut)
	}
	for _, name := range []string{"input", "output", "arch", "entropy", "compression", "bypass", "decoy", "method", "params", "run-thread", "exit"} {
		if _, ok := donut.Options[name]; !ok {
			t.Fatalf("donut is missing option %q", name)
		}
	}
	for _, path := range []string{"src/donut.c", "src/loader/loader.c", "src/loader/mem_shim.c", "src/lib/aplib64.a"} {
		if _, err := os.Stat(filepath.Join(moduleDir, path)); err != nil {
			t.Fatalf("donut source is missing %s: %v", path, err)
		}
	}
}

func TestWriteSourceFileRejectsReadOnlyRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.c")
	if err := os.WriteFile(path, []byte("int x;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := sourceRoot{Name: "dep", Dir: dir}
	if _, err := writeSourceFile(root, "x.c", "int x;", "int y;"); err == nil {
		t.Fatal("read-only root accepted a write")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "int x;\n" {
		t.Fatal("read-only root was modified")
	}
}

func TestSanitizeKnowledgeTextDropsTerminalAndBidiControls(t *testing.T) {
	in := "safe\x1b]0;title\x07 \u0085 \u202e text\nnext\tline"
	got := sanitizeKnowledgeText(in)
	for _, bad := range []string{"\x1b", "\x07", "\u0085", "\u202e"} {
		if strings.Contains(got, bad) {
			t.Fatalf("sanitized text still contains %q: %q", bad, got)
		}
	}
	if !strings.Contains(got, "safe") || !strings.Contains(got, "text\nnext\tline") {
		t.Fatalf("sanitized text lost prose: %q", got)
	}
}

func TestNewMCPClientRejectsUnsafeURLs(t *testing.T) {
	for _, raw := range []string{
		"ftp://example.test/mcp",
		"file:///etc/passwd",
		"https://user:pass@example.test/mcp",
		"http://",
	} {
		if _, err := newMCPClient(raw); err == nil {
			t.Errorf("newMCPClient(%q) accepted an unsafe URL", raw)
		}
	}
	client, err := newMCPClient("http://127.0.0.1:1337/mcp")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.test/mcp", nil)
	if err := client.http.CheckRedirect(req, nil); err == nil {
		t.Fatal("redirect to another origin was accepted")
	}
	req, _ = http.NewRequest(http.MethodGet, "http://127.0.0.1:1337/other", nil)
	if err := client.http.CheckRedirect(req, nil); err != nil {
		t.Fatalf("same-origin redirect rejected: %v", err)
	}
}

func TestKnowledgeSidecarsArePrivate(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "knowledge.db")
	db, err := OpenKnowledgeDB(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, name := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 600", filepath.Base(name), perm)
		}
	}
}

func TestValidateProducerPathOption(t *testing.T) {
	base := t.TempDir()
	inside := filepath.Join(base, "decoy.dll")
	if err := os.WriteFile(inside, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateProducerPathOption("decoy", inside, base); err != nil {
		t.Fatalf("inside file rejected: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "secret.dll")
	if err := os.WriteFile(outside, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateProducerPathOption("decoy", outside, base); err == nil {
		t.Fatal("decoy outside the payload directory was accepted")
	}
	link := filepath.Join(base, "link.dll")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := validateProducerPathOption("decoy", link, base); err == nil {
		t.Fatal("symlink decoy was accepted")
	}
	if err := validateProducerPathOption("params", "anything", base); err != nil {
		t.Fatalf("non-path option rejected: %v", err)
	}
}

func TestNormalizeEvolveConfigCapsLoops(t *testing.T) {
	dir := t.TempDir()
	shell := filepath.Join(dir, "shellcode.bin")
	if err := os.WriteFile(shell, []byte{0x90}, 0o600); err != nil {
		t.Fatal(err)
	}
	base := EvolveConfig{Module: "loader_windows", ModuleDir: dir, Shellcode: shell, StoreRoot: dir, Stages: []string{"dynamic"}}
	tooMany := base
	tooMany.Iterations = maxEvolveIterations + 1
	if err := normalizeEvolveConfig(&tooMany); err == nil {
		t.Fatal("iteration cap was not enforced")
	}
	tooManyTurns := base
	tooManyTurns.Turns = maxEvolveTurns + 1
	if err := normalizeEvolveConfig(&tooManyTurns); err == nil {
		t.Fatal("turn cap was not enforced")
	}
}

func TestRestoreSourceFileRollsBackEdit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.c")
	original := []byte("int x;\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	root := sourceRoot{Name: "module", Dir: dir, Writable: true}
	write, err := writeSourceFile(root, "x.c", "int x;", "int y;")
	if err != nil {
		t.Fatal(err)
	}
	if err := restoreSourceFile(write.Path, write.Original); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(original) {
		t.Fatalf("rollback left %q", data)
	}
}
