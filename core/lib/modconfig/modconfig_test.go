package modconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/coffloader"
)

// writeConfig writes a module manifest into a temp dir and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

const twoModuleConfig = `[
  {
    "name": "mod_a",
    "platform": "Windows",
    "agent_config": {"type": "coff", "files": ["_bin/a.x64.o", "_bin/a.x86.o"]},
    "parameters": [
      {"name": "params", "description": "raw params", "type": "cstr", "default": ""},
      {"name": "pid", "description": "process id", "type": "int", "default": "7"},
      {"name": "mask", "description": "optional short", "type": "short"},
      {"name": "wide", "description": "wide string", "type": "wstr"},
      {"name": "blob", "description": "binary", "type": "binary"}
    ],
    "invocation": {"coff_export": "go"}
  },
  {
    "name": "mod_b",
    "platform": "Windows",
    "agent_config": {"type": "coff", "files": ["_bin/b.x64.o"]},
    "parameters": [
      {"name": "params", "description": "raw params", "type": "cstr"}
    ],
    "invocation": {"coff_export": "go"}
  }
]`

func TestReadConfigsDerivesCoffInvocation(t *testing.T) {
	configs, err := ReadConfigs(writeConfig(t, twoModuleConfig))
	if err != nil {
		t.Fatalf("ReadConfigs: %v", err)
	}
	if len(configs) != 2 {
		t.Fatalf("expected 2 modules, got %d", len(configs))
	}

	a := configs[0]
	if a.Name != "mod_a" {
		t.Fatalf("first module is %q, want mod_a", a.Name)
	}
	if a.Invocation.Coff == nil {
		t.Fatal("mod_a has no COFF invocation")
	}
	if a.Invocation.Coff.Export != "go" {
		t.Errorf("export = %q, want go", a.Invocation.Coff.Export)
	}
	if len(a.Invocation.Coff.Args) != 5 {
		t.Fatalf("mod_a has %d COFF args, want 5 (in declaration order)", len(a.Invocation.Coff.Args))
	}
	wantParams := []string{"params", "pid", "mask", "wide", "blob"}
	for i, want := range wantParams {
		if got := a.Invocation.Coff.Args[i].Param; got != want {
			t.Errorf("arg %d = %s, want %s", i, got, want)
		}
	}

	// Windows COFF modules automatically depend on the COFFLoader DLL.
	foundDep := false
	for _, dep := range a.Dependencies {
		if dep == "coffloader" {
			foundDep = true
			break
		}
	}
	if !foundDep {
		t.Errorf("mod_a dependencies = %v, want to include coffloader", a.Dependencies)
	}
}

func TestResolveCoffArgsTypesAndOrder(t *testing.T) {
	configs, err := ReadConfigs(writeConfig(t, twoModuleConfig))
	if err != nil {
		t.Fatalf("ReadConfigs: %v", err)
	}
	config := configs[0]

	args, err := ResolveCoffArgs(config, map[string]string{
		"params": "/luid:3ea8 /server:krbtgt",
		"pid":    "42",
		"wide":   "host",
		"blob":   "aGk=",
		// mask intentionally omitted: the empty short must be zero-filled.
	})
	if err != nil {
		t.Fatalf("ResolveCoffArgs: %v", err)
	}

	want := []coffloader.CoffArg{
		{WireType: "z", Value: "/luid:3ea8 /server:krbtgt"},
		{WireType: "i", Value: float64(42)},
		{WireType: "s", Value: float64(0)},
		{WireType: "Z", Value: "host"},
		{WireType: "b", Value: "aGk="},
	}
	if len(args) != len(want) {
		t.Fatalf("got %d args, want %d", len(args), len(want))
	}
	for i := range want {
		if args[i].WireType != want[i].WireType || args[i].Value != want[i].Value {
			t.Errorf("arg %d = %#v, want %#v", i, args[i], want[i])
		}
	}
}

func TestResolveCoffArgsDefaults(t *testing.T) {
	configs, err := ReadConfigs(writeConfig(t, twoModuleConfig))
	if err != nil {
		t.Fatalf("ReadConfigs: %v", err)
	}

	// No flags supplied: declared defaults must still be packed, and
	// non-required empty strings/numerics must not error.
	args, err := ResolveCoffArgs(configs[1], nil)
	if err != nil {
		t.Fatalf("ResolveCoffArgs: %v", err)
	}
	if len(args) != 1 || args[0].WireType != "z" || args[0].Value != "" {
		t.Fatalf("mod_b default args = %#v, want one empty z arg", args)
	}
}

func TestResolveCoffArgsRejectsBadNumber(t *testing.T) {
	configs, err := ReadConfigs(writeConfig(t, twoModuleConfig))
	if err != nil {
		t.Fatalf("ReadConfigs: %v", err)
	}
	if _, err := ResolveCoffArgs(configs[0], map[string]string{"pid": "not-a-number"}); err == nil {
		t.Fatal("expected an error for a non-numeric int parameter")
	}
}

func TestResolveCoffArgsRejectsNonCoff(t *testing.T) {
	path := writeConfig(t, `{
	  "name": "script_only",
	  "agent_config": {"type": "starlark", "files": ["run.star"]},
	  "parameters": [{"name": "arg", "description": "an arg", "type": "cstr"}],
	  "invocation": {"argv": [{"literal": "run.star"}]}
	}`)
	configs, err := ReadConfigs(path)
	if err != nil {
		t.Fatalf("ReadConfigs: %v", err)
	}
	if _, err := ResolveCoffArgs(configs[0], nil); err == nil {
		t.Fatal("expected an error for a non-COFF module")
	}
}

func TestSelectModule(t *testing.T) {
	configs, err := ReadConfigs(writeConfig(t, twoModuleConfig))
	if err != nil {
		t.Fatalf("ReadConfigs: %v", err)
	}

	byName, err := SelectModule(configs, "mod_b", "")
	if err != nil {
		t.Fatalf("SelectModule by name: %v", err)
	}
	if byName.Name != "mod_b" {
		t.Errorf("by name = %q, want mod_b", byName.Name)
	}

	byPayload, err := SelectModule(configs, "", "a.x64.o")
	if err != nil {
		t.Fatalf("SelectModule by payload: %v", err)
	}
	if byPayload.Name != "mod_a" {
		t.Errorf("by payload = %q, want mod_a", byPayload.Name)
	}

	if _, err := SelectModule(configs, "missing", ""); err == nil {
		t.Error("expected an error for an unknown module name")
	}
	if _, err := SelectModule(configs, "", ""); err == nil {
		t.Error("expected an error when an ambiguous config needs -module")
	}
}

func TestSelectModuleSingleFallback(t *testing.T) {
	configs, err := ReadConfigs(writeConfig(t, twoModuleConfig))
	if err != nil {
		t.Fatalf("ReadConfigs: %v", err)
	}
	// A payload that matches nothing still resolves when the manifest has
	// exactly one module.
	selected, err := SelectModule(configs[1:], "", "unrelated.o")
	if err != nil {
		t.Fatalf("SelectModule single fallback: %v", err)
	}
	if selected.Name != "mod_b" {
		t.Errorf("selected = %q, want mod_b", selected.Name)
	}
}

func TestFindConfigFile(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "_bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cfg := filepath.Join(root, "config.json")
	if err := os.WriteFile(cfg, []byte(`{"name":"x","agent_config":{"type":"coff","files":["_bin/x.x64.o"]}}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	found, err := FindConfigFile(filepath.Join(binDir, "x.x64.o"))
	if err != nil {
		t.Fatalf("FindConfigFile: %v", err)
	}
	absFound, _ := filepath.Abs(found)
	absWant, _ := filepath.Abs(cfg)
	if absFound != absWant {
		t.Errorf("found %s, want %s", absFound, absWant)
	}

	if _, err := FindConfigFile(filepath.Join(t.TempDir(), "nothing.o")); err == nil {
		t.Error("expected an error when no config.json exists")
	}
}

func TestTypeToWireToken(t *testing.T) {
	cases := map[string]string{
		"cstr": "z", "string": "z", "str": "z", "lpstr": "z",
		"wstr": "Z", "wstring": "Z", "lpwstr": "Z",
		"int": "i", "dword": "i", "uint32": "i", "bool": "i", "port": "i",
		"short": "s", "word": "s", "int16": "s",
		"binary": "b", "base64": "b",
		"z": "z", "Z": "Z", "i": "i", "s": "s", "b": "b",
		"unknown": "",
	}
	for in, want := range cases {
		if got := typeToWireToken(in); got != want {
			t.Errorf("typeToWireToken(%q) = %q, want %q", in, got, want)
		}
	}
}
