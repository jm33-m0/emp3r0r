package assistant

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/controllers"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func testModule() *def.ModuleConfig {
	return &def.ModuleConfig{
		Name:     "demo",
		Comment:  "Demo module",
		Platform: "Generic",
		Options: def.ModOptions{
			"filter": {
				Name:     "filter",
				Desc:     "Filter expression",
				Val:      "(objectclass=*)",
				Type:     "string",
				Required: true,
			},
			"scope": {
				Name: "scope",
				Desc: "Search scope",
				Val:  "0",
				Type: "int",
			},
			"ldaps": {
				Name: "ldaps",
				Desc: "Use LDAPS",
				Val:  "false",
				Type: "bool",
			},
			"token": {
				Name:     "token",
				Desc:     "Injected token",
				Type:     "string",
				Internal: true,
			},
		},
		Examples: []string{"demo --filter '(objectClass=user)'"},
		Help:     "Longer description.",
	}
}

func TestUsageLine(t *testing.T) {
	got := usageLine(testModule())
	want := `demo --filter '(objectclass=*)' [--ldaps] [--scope 0]`
	if got != want {
		t.Fatalf("usageLine = %q, want %q", got, want)
	}
}

func TestDescribeModuleIncludesHelpMetadata(t *testing.T) {
	mod := testModule()
	mod.Path = "/workspace/modules/demo"
	info := describeModule(mod)
	if len(info.Examples) != 1 || info.Help == "" {
		t.Fatalf("missing help metadata: %+v", info)
	}
	if info.Path != mod.Path {
		t.Fatalf("path = %q, want %q", info.Path, mod.Path)
	}
	if len(info.Parameters) != 4 {
		t.Fatalf("parameters = %d", len(info.Parameters))
	}
}

func TestReviewCommandValidatesAndRenders(t *testing.T) {
	mod := testModule()
	def.Modules.Store(mod.Name, mod)
	t.Cleanup(func() { def.Modules.Delete(mod.Name) })

	rt := &toolRuntime{cfg: DefaultConfig()}
	raw, _ := json.Marshal(reviewArgs{
		Module: "demo",
		Flags: map[string]any{
			"filter": "(objectClass=user)",
			"scope":  "2",
			"ldaps":  true,
		},
	})
	out, err := rt.reviewCommand(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	result := out.(map[string]any)
	if result["valid"] != true {
		t.Fatalf("expected valid command, got %+v", result)
	}
	command := result["command"].(string)
	want := `demo --filter '(objectClass=user)' --ldaps --scope 2`
	if command != want {
		t.Fatalf("command = %q, want %q", command, want)
	}
}

func TestReviewCommandRejectsUnknownAndMissingRequired(t *testing.T) {
	mod := testModule()
	def.Modules.Store(mod.Name, mod)
	t.Cleanup(func() { def.Modules.Delete(mod.Name) })

	rt := &toolRuntime{cfg: DefaultConfig()}
	raw, _ := json.Marshal(reviewArgs{
		Module: "demo",
		Flags:  map[string]any{"nope": "value"},
	})
	out, err := rt.reviewCommand(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	result := out.(map[string]any)
	if result["valid"] != false {
		t.Fatalf("expected invalid command, got %+v", result)
	}
	problems := result["problems"].([]string)
	if !containsString(problems, "unknown option --nope") {
		t.Fatalf("missing unknown-option problem: %v", problems)
	}

	noDefault := testModule()
	noDefault.Options["filter"].Val = ""
	def.Modules.Store(noDefault.Name, noDefault)
	raw, _ = json.Marshal(reviewArgs{Module: "demo"})
	out, err = rt.reviewCommand(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	result = out.(map[string]any)
	problems = result["problems"].([]string)
	if !containsString(problems, "required option --filter is missing") {
		t.Fatalf("missing required-option problem: %v", problems)
	}
}

func TestSliceOutputTail(t *testing.T) {
	got := sliceOutput("id", "console-cache", "0123456789", 0, 4, true)
	if got["output"] != "6789" || got["truncated"] != true {
		t.Fatalf("unexpected tail slice: %+v", got)
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if strings.Contains(item, want) {
			return true
		}
	}
	return false
}

func TestSummarizeProcessOutputUsesRawCBOR(t *testing.T) {
	data, err := cbor.Marshal([]util.ProcEntry{{
		PID:     1,
		PPID:    0,
		Name:    "init",
		Cmdline: "/sbin/init",
		Token:   "root",
		UID:     "0",
	}})
	if err != nil {
		t.Fatal(err)
	}
	summary, ok := summarizeOutput("ps", string(data), false).(map[string]any)
	if !ok {
		t.Fatal("summary is not a map")
	}
	if summary["format"] != "process list" {
		t.Fatalf("format = %v", summary["format"])
	}
	rows, ok := summary["rows"].([][]string)
	if !ok || len(rows) != 1 {
		t.Fatalf("rows = %#v", summary["rows"])
	}
	if rows[0][4] != "init" {
		t.Fatalf("row = %#v", rows[0])
	}
}

func TestTableSummarySanitizesUntrustedCells(t *testing.T) {
	out := tableSummary("table", &controllers.ParsedCommandOutput{
		Headers: []string{"name\ninjected"},
		Rows:    [][]string{{"file\nrun me", strings.Repeat("x", 2000)}},
	}, false)
	summary := out.(map[string]any)
	headers := summary["headers"].([]string)
	if headers[0] != "name injected" {
		t.Fatalf("header = %q", headers[0])
	}
	rows := summary["rows"].([][]string)
	if rows[0][0] != "file run me" {
		t.Fatalf("cell = %q", rows[0][0])
	}
	if len(rows[0][1]) != 1024 {
		t.Fatalf("long cell length = %d", len(rows[0][1]))
	}
}

func TestListModulesIncludesLocalModulesForOtherPlatforms(t *testing.T) {
	def.Modules.Store("zz_local_windows", &def.ModuleConfig{
		Name: "zz_local_windows", Comment: "local Windows loader",
		Platform: "Windows", IsLocal: true,
	})
	t.Cleanup(func() { def.Modules.Delete("zz_local_windows") })

	rt := &toolRuntime{
		cfg:    DefaultConfig(),
		target: &def.Emp3r0rAgent{GOOS: "linux"},
	}
	out, err := rt.listModules(context.Background(), json.RawMessage(`{"query":"zz_local_windows"}`))
	if err != nil {
		t.Fatal(err)
	}
	rows := out.(map[string]any)["modules"].([]moduleRow)
	if len(rows) != 1 || rows[0].Name != "zz_local_windows" {
		t.Fatalf("local module hidden by target platform: %+v", rows)
	}
}

func TestListModulesHintsWhenNothingMatches(t *testing.T) {
	def.Modules.Store("zz_hint_module", &def.ModuleConfig{
		Name: "zz_hint_module", Comment: "hint helper", Platform: "Generic",
	})
	t.Cleanup(func() { def.Modules.Delete("zz_hint_module") })

	rt := &toolRuntime{cfg: DefaultConfig()}
	out, err := rt.listModules(context.Background(), json.RawMessage(`{"query":"zzzz-no-such-module"}`))
	if err != nil {
		t.Fatal(err)
	}
	result := out.(map[string]any)
	hint, _ := result["hint"].(string)
	if !strings.Contains(hint, "zz_hint_module") {
		t.Fatalf("hint = %q", hint)
	}
}
