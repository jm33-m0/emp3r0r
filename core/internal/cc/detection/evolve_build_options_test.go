package detection

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

const loaderBuildOptionConfig = `[
  {
    "name": "loader_windows",
    "build": "bash ./build.sh",
    "is_local": true,
    "parameters": [
      {"name": "shellcode", "type": "string", "required": true},
      {"name": "format", "type": "string", "default": "service", "choices": ["service", "exe", "dll"]},
      {"name": "inject", "type": "string", "default": "apc", "choices": ["apc", "ct", "self"]},
      {"name": "smw", "type": "string", "default": "on", "choices": ["on", "off"]},
      {"name": "process", "type": "string", "default": "dllhost.exe"},
      {"name": "arch", "type": "string", "default": "x64", "choices": ["x64", "x86"]},
      {"name": "output", "type": "string"}
    ]
  }
]`

const crystalPackBuildOptionConfig = `[
  {
    "name": "crystal_pack",
    "build": "bash ./build.sh",
    "is_local": true,
    "parameters": [
      {"name": "dll", "type": "string", "required": true},
      {"name": "output", "type": "string"},
      {"name": "link_options", "type": "string", "default": ""}
    ]
  }
]`

func newBuildOptionTestEvolver(t *testing.T) *evolver {
	t.Helper()
	moduleDir := t.TempDir()
	producerDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(moduleDir, "config.json"), []byte(loaderBuildOptionConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(producerDir, "config.json"), []byte(crystalPackBuildOptionConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &evolver{
		cfg: EvolveConfig{
			LoopID: "loop", Module: "loader_windows", ModuleDir: moduleDir,
			ProducerDirs: map[string]string{"crystal_pack": producerDir},
		},
		logf: func(logging.Class, string, ...any) {},
	}
	e.roots = e.sourceRoots()
	e.initBuildOptions(initialBuildOptions(e.cfg))
	return e
}

func callBuildOptions(t *testing.T, e *evolver, args string) toolResult {
	t.Helper()
	result, err := e.buildOptionsTool().Call(context.Background(), json.RawMessage(args), nil)
	if err != nil {
		t.Fatal(err)
	}
	return toolResult{isError: result.IsError, text: result.Flatten()}
}

type toolResult struct {
	isError bool
	text    string
}

func TestBuildOptionsListsAndSetsPayloadFlags(t *testing.T) {
	e := newBuildOptionTestEvolver(t)
	listed := callBuildOptions(t, e, `{}`)
	if listed.isError {
		t.Fatalf("list failed: %s", listed.text)
	}
	var view struct {
		Module    string            `json:"module"`
		Options   map[string]string `json:"options"`
		Available []optionView      `json:"available"`
	}
	if err := json.Unmarshal([]byte(listed.text), &view); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if view.Module != "loader_windows" || len(view.Available) != 7 {
		t.Fatalf("unexpected list: %+v", view)
	}
	for _, opt := range view.Available {
		if opt.Name == "format" && opt.Default != "service" {
			t.Fatalf("format default = %q", opt.Default)
		}
	}

	set := callBuildOptions(t, e, `{"options":{"format":"exe","inject":"self","smw":"off"}}`)
	if set.isError {
		t.Fatalf("set failed: %s", set.text)
	}
	got := e.buildOptionsSnapshot()
	if got["format"] != "exe" || got["inject"] != "self" || got["smw"] != "off" {
		t.Fatalf("options = %+v", got)
	}

	reset := callBuildOptions(t, e, `{"reset":["format"]}`)
	if reset.isError {
		t.Fatalf("reset failed: %s", reset.text)
	}
	if _, ok := e.buildOptionsSnapshot()["format"]; ok {
		t.Fatal("reset did not remove format")
	}

	empty := callBuildOptions(t, e, `{"options":{"process":""}}`)
	if empty.isError {
		t.Fatalf("empty option failed: %s", empty.text)
	}
	if _, ok := e.buildOptionsSnapshot()["process"]; ok {
		t.Fatal("empty value was not treated as a reset")
	}

	hostOwned := callBuildOptions(t, e, `{"options":{"shellcode":"/tmp/x"}}`)
	if !hostOwned.isError {
		t.Fatal("host-filled shellcode was accepted")
	}
	unknown := callBuildOptions(t, e, `{"options":{"nope":"x"}}`)
	if !unknown.isError {
		t.Fatal("unknown option was accepted")
	}
	badChoice := callBuildOptions(t, e, `{"options":{"inject":"thread"}}`)
	if !badChoice.isError {
		t.Fatal("invalid choice was accepted")
	}
}

func TestBuildOptionsProducerPersistence(t *testing.T) {
	e := newBuildOptionTestEvolver(t)
	set := callBuildOptions(t, e, `{"module":"crystal_pack","options":{"link_options":"+shatter +regdance"}}`)
	if set.isError {
		t.Fatalf("producer set failed: %s", set.text)
	}
	if got := e.producerOptionsSnapshot("crystal_pack")["link_options"]; got != "+shatter +regdance" {
		t.Fatalf("link_options = %q", got)
	}
	if input := callBuildOptions(t, e, `{"module":"crystal_pack","options":{"dll":"/tmp/a.dll"}}`); !input.isError {
		t.Fatal("host-filled dll input was accepted")
	}
	e.replaceProducerOptions("crystal_pack", map[string]string{"link_options": "+mutate"})
	merged := e.mergeProducerOptions("crystal_pack", map[string]string{"link_options": "+shatter"})
	if merged["link_options"] != "+shatter" {
		t.Fatalf("per-call option did not override: %+v", merged)
	}
}

func TestSummaryBuildOptionsRestoresState(t *testing.T) {
	e := newBuildOptionTestEvolver(t)
	e.replaceBuildOptions(map[string]string{"format": "dll"})
	e.replaceProducerOptions("crystal_pack", map[string]string{"link_options": "+shatter"})
	e.activeProducer = "crystal_pack"
	summary := cycleSummary{
		BuildOptions:    map[string]string{"format": "exe", "smw": "off"},
		Producer:        "crystal_pack",
		ProducerOptions: map[string]string{"link_options": "+mutate"},
	}
	e.summaryBuildOptions(&summary)
	if got := e.buildOptionsSnapshot(); got["format"] != "exe" || got["smw"] != "off" {
		t.Fatalf("build options = %+v", got)
	}
	if got := e.activeProducerOptions()["link_options"]; got != "+mutate" {
		t.Fatalf("producer options = %q", got)
	}
}

func TestPayloadBuildFlagsProtectHostValues(t *testing.T) {
	e := newBuildOptionTestEvolver(t)
	e.replaceBuildOptions(map[string]string{
		"format": "exe", "inject": "self", "shellcode": "/tmp/evil.bin",
		"output": "/tmp/evil.exe", "arch": "x86",
	})
	flags := e.payloadBuildFlags("agent.bin")
	if flags["shellcode"] != "agent.bin" || flags["arch"] != "x64" {
		t.Fatalf("host values overwritten: %+v", flags)
	}
	if _, ok := flags["output"]; ok {
		t.Fatalf("host output override leaked: %+v", flags)
	}
	if flags["format"] != "exe" || flags["inject"] != "self" {
		t.Fatalf("model options missing: %+v", flags)
	}
}

func TestProducerOptionsPersistForNextBuild(t *testing.T) {
	producerDir := t.TempDir()
	config := `[{"name":"donut","build":"true","is_local":true,"parameters":[
		{"name":"input","type":"string","required":true},
		{"name":"output","type":"string"},
		{"name":"args","type":"string"}]}]`
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
	var captured []map[string]string
	e := &evolver{
		cfg: EvolveConfig{
			LoopID: "loop", Module: "loader_windows", ModuleDir: t.TempDir(),
			Shellcode: shellcode, StoreRoot: t.TempDir(),
			ProducerDirs: map[string]string{"donut": producerDir},
			BuildProducer: func(_ string, _ string, flags map[string]string) (string, error) {
				snapshot := map[string]string{}
				for key, value := range flags {
					snapshot[key] = value
				}
				captured = append(captured, snapshot)
				out := flags["output"]
				body := strings.Repeat("X", 40000)
				if err := os.WriteFile(out, []byte(body), 0o600); err != nil {
					return "", err
				}
				return "[+] generated payload: " + out + " (40000 bytes)\n", nil
			},
		},
		logf: func(logging.Class, string, ...any) {},
	}
	e.roots = e.sourceRoots()
	e.agentArtifact = seedExe
	if _, _, _, err := e.buildShellcodeWithProducer(context.Background(), "donut", map[string]string{"args": "--test"}, "first"); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 1 || captured[0]["args"] != "--test" {
		t.Fatalf("first build flags = %+v", captured)
	}
	if _, _, _, err := e.buildShellcodeWithProducer(context.Background(), "donut", nil, "rotation"); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 2 || captured[1]["args"] != "--test" {
		t.Fatalf("rotation lost the producer options: %+v", captured)
	}
	if got := e.activeProducerOptions()["args"]; got != "--test" {
		t.Fatalf("persisted args = %q", got)
	}
}
