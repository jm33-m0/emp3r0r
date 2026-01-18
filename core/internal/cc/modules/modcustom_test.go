package modules

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func TestReadModConfig(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir, err := os.MkdirTemp("", "emp3r0r-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Define a sample JSON config
	jsonConfig := `{
		"name": "test_module",
		"build": "go build",
		"author": "tester",
		"date": "2023-10-27",
		"comment": "A test module",
		"is_local": true,
		"platform": "Linux",
		"path": "/tmp/test_module",
		"fileless": false,
		"agent_config": {
			"exec": "test_exec",
			"files": ["file1", "file2"],
			"in_memory": true,
			"type": "go",
			"interactive": false
		},
		"parameters": [
			{
				"name": "option1",
				"description": "Description 1",
				"default": "value1",
				"choices": ["value1", "value2"],
				"type": "string",
				"required": true
			}
		],
		"invocation": {
			"argv": [
				{"literal": "test_exec"},
				{"param": "option1"}
			]
		}
	}`

	// Write the config to a file
	configFile := filepath.Join(tmpDir, "config.json")
	err = os.WriteFile(configFile, []byte(jsonConfig), 0o644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Call the function to test
	config, err := readModCondig(configFile)
	if err != nil {
		t.Fatalf("readModCondig failed: %v", err)
	}

	// Verify the results
	if config.Name != "test_module" {
		t.Errorf("Expected Name 'test_module', got '%s'", config.Name)
	}
	if config.Build != "go build" {
		t.Errorf("Expected Build 'go build', got '%s'", config.Build)
	}
	if config.Author != "tester" {
		t.Errorf("Expected Author 'tester', got '%s'", config.Author)
	}
	if !config.IsLocal {
		t.Errorf("Expected IsLocal true, got false")
	}
	if config.AgentConfig.Exec != "test_exec" {
		t.Errorf("Expected AgentConfig.Exec 'test_exec', got '%s'", config.AgentConfig.Exec)
	}
	if len(config.AgentConfig.Files) != 2 {
		t.Errorf("Expected 2 files, got %d", len(config.AgentConfig.Files))
	}
	if !config.AgentConfig.InMemory {
		t.Errorf("Expected AgentConfig.InMemory true, got false")
	}

	opt, ok := config.Options["option1"]
	if !ok {
		t.Fatalf("Expected option1 to exist")
	}
	if opt.Val != "value1" {
		t.Errorf("Expected option1 value 'value1', got '%s'", opt.Val)
	}
}

func TestReadModConfigPartial(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir, err := os.MkdirTemp("", "emp3r0r-test-partial")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Define a sample JSON config with missing fields
	jsonConfig := `{
		"name": "test_module_partial",
		"parameters": [],
		"invocation": {"argv": []}
	}`

	// Write the config to a file
	configFile := filepath.Join(tmpDir, "config.json")
	err = os.WriteFile(configFile, []byte(jsonConfig), 0o644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Call the function to test
	config, err := readModCondig(configFile)
	if err != nil {
		t.Fatalf("readModCondig failed: %v", err)
	}

	// Verify the results
	if config.Name != "test_module_partial" {
		t.Errorf("Expected Name 'test_module_partial', got '%s'", config.Name)
	}
	if config.Build != "" {
		t.Errorf("Expected Build '', got '%s'", config.Build)
	}
	if config.IsLocal {
		t.Errorf("Expected IsLocal false, got true")
	}
}

func TestResolveInvocation(t *testing.T) {
	config := &def.ModuleConfig{
		AgentConfig: def.AgentModuleConfig{Type: "coff"},
		Invocation: def.InvocationSpec{
			Argv: []def.InvocationArg{
				{Literal: "runner"},
				{Flag: "-p", Param: "port"},
			},
			StdinParam: "message",
			Coff: &def.CoffInvocation{
				Export: "Run",
				Args:   []def.CoffArgSpec{{Param: "port", WireType: "DWORD"}},
			},
		},
		Options: def.ModOptions{
			"port":    {Name: "port", Val: "8080", Type: "uint", Required: true},
			"message": {Name: "message", Val: "hello", Type: "string"},
		},
	}

	inv, err := resolveInvocation(config, nil)
	if err != nil {
		t.Fatalf("resolveInvocation: %v", err)
	}

	if len(inv.Argv) != 3 || inv.Argv[0] != "runner" || inv.Argv[1] != "-p" || inv.Argv[2] != "8080" {
		t.Fatalf("unexpected argv: %v", inv.Argv)
	}

	if inv.Stdin != "hello" {
		t.Fatalf("stdin mismatch: %q", inv.Stdin)
	}

	if inv.Coff == nil || len(inv.Coff.Args) != 1 {
		t.Fatalf("expected one COFF arg")
	}
	if inv.Coff.Args[0].WireType != "DWORD" {
		t.Fatalf("wire type mismatch: %s", inv.Coff.Args[0].WireType)
	}
}

func TestResolveInvocationMissingRequired(t *testing.T) {
	config := &def.ModuleConfig{
		AgentConfig: def.AgentModuleConfig{Type: "elf"},
		Invocation:  def.InvocationSpec{Argv: []def.InvocationArg{{Param: "must"}}},
		Options: def.ModOptions{
			"must": {Name: "must", Type: "string", Required: true, Val: ""},
		},
	}

	if _, err := resolveInvocation(config, nil); err == nil {
		t.Fatalf("expected error for missing required option")
	}
}

func TestReadModConfigFullInvocationAndAgentConfig(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "emp3r0r-full")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	jsonConfig := `{
		"name": "coff_mod",
		"build": "make",
		"author": "tester",
		"date": "2025-01-01",
		"comment": "full coverage",
		"is_local": false,
		"platform": "Windows",
		"path": "",
		"fileless": true,
		"agent_config": {
			"exec": "mod.exe",
			"files": ["mod.exe"],
			"in_memory": false,
			"type": "coff",
			"interactive": false,
			"work_dir": "C:/tmp",
			"needs_root": true
		},
		"parameters": [
			{
				"name": "flagged",
				"description": "flag option",
				"default": "on",
				"choices": ["on", "off"],
				"type": "enum",
				"required": true,
				"pattern": "on|off",
				"encoding": "utf8",
				"secret": false,
				"min": 0,
				"max": 1
			}
		],
		"invocation": {
			"argv": [
				{"literal": "runner"},
				{"flag": "-o", "param": "flagged"}
			],
			"stdin_param": "flagged",
			"timeout_seconds": 42,
			"coff": {
				"export": "Run",
				"args": [{"param": "flagged", "literal": "on", "wire_type": "LPSTR", "encoding": "utf8"}]
			}
		}
	}`

	configFile := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configFile, []byte(jsonConfig), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	config, err := readModCondig(configFile)
	if err != nil {
		t.Fatalf("readModCondig: %v", err)
	}

	if got := config.Invocation.TimeoutSeconds; got != 42 {
		t.Fatalf("timeout mismatch: %d", got)
	}
	if config.Invocation.StdinParam != "flagged" {
		t.Fatalf("stdin param mismatch: %s", config.Invocation.StdinParam)
	}
	if config.Invocation.Coff == nil || config.Invocation.Coff.Export != "Run" || len(config.Invocation.Coff.Args) != 1 {
		t.Fatalf("coff invocation parsed incorrectly: %+v", config.Invocation.Coff)
	}
	opt := config.Options["flagged"]
	if opt == nil || opt.Required != true || opt.Pattern == "" || opt.Encoding != "utf8" || opt.Min == nil || opt.Max == nil {
		t.Fatalf("option metadata missing: %+v", opt)
	}
	if config.AgentConfig.WorkDir != "C:/tmp" || !config.AgentConfig.NeedsRoot {
		t.Fatalf("agent config fields not parsed: %+v", config.AgentConfig)
	}
}

func TestReadModConfigLegacyOptions(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "emp3r0r-legacy")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	jsonConfig := `{
		"name": "legacy_mod",
		"options": {
			"old": {"opt_name": "old", "opt_desc": "legacy", "opt_val": "x", "opt_vals": ["x"]}
		},
		"parameters": [],
		"invocation": {"argv": []}
	}`
	configFile := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configFile, []byte(jsonConfig), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	config, err := readModCondig(configFile)
	if err != nil {
		t.Fatalf("readModCondig: %v", err)
	}

	opt := config.Options["old"]
	if opt == nil || opt.Val != "x" || opt.Type != "string" {
		t.Fatalf("legacy option not parsed: %+v", opt)
	}
}

func TestUpdateModuleHelp(t *testing.T) {
	modName := "help_mod"
	config := &def.ModuleConfig{
		Name: modName,
		Options: def.ModOptions{
			"foo": {Name: "foo", Desc: "bar"},
		},
	}
	def.Modules[modName] = config
	defer delete(def.Modules, modName)

	if err := updateModuleHelp(config); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if def.Modules[modName].Options["foo"].Desc != "bar" {
		t.Fatalf("help map not applied")
	}

	config.Options["foo"].Desc = ""
	if err := updateModuleHelp(config); err == nil {
		t.Fatalf("expected error when desc missing")
	}
}

func TestInitModulesLoadsLocalModule(t *testing.T) {
	tmpRoot, err := os.MkdirTemp("", "emp3r0r-init")
	if err != nil {
		t.Fatalf("temp root: %v", err)
	}
	defer os.RemoveAll(tmpRoot)

	moduleDir := filepath.Join(tmpRoot, "mods")
	if err := os.MkdirAll(filepath.Join(moduleDir, "foo"), 0o755); err != nil {
		t.Fatalf("mkdir module: %v", err)
	}

	jsonConfig := `{
		"name": "foo",
		"is_local": true,
		"agent_config": {"exec": "foo.sh", "type": "bash"},
		"invocation": {"argv": []}
	}`
	configFile := filepath.Join(moduleDir, "foo", "config.json")
	if err := os.WriteFile(configFile, []byte(jsonConfig), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	origModules := len(def.Modules)
	origRunners := ModuleRunners
	origModuleDirs := live.ModuleDirs
	origWorkspace := live.EmpWorkSpace
	ModuleRunners = make(map[string]func())
	for k, v := range origRunners {
		ModuleRunners[k] = v
	}
	defer func() {
		for k := range ModuleRunners {
			delete(ModuleRunners, k)
		}
		for k, v := range origRunners {
			ModuleRunners[k] = v
		}
		delete(def.Modules, "foo")
		live.ModuleDirs = origModuleDirs
		live.EmpWorkSpace = origWorkspace
	}()

	live.EmpWorkSpace = filepath.Join(tmpRoot, "workspace")
	live.ModuleDirs = []string{moduleDir}

	InitModules()

	if len(def.Modules) != origModules+1 {
		t.Fatalf("module not loaded")
	}
	if _, ok := ModuleRunners["foo"]; !ok {
		t.Fatalf("custom runner not registered")
	}
	loaded, ok := def.Modules["foo"]
	if !ok {
		t.Fatalf("module not stored")
	}
	expectedPath := filepath.Join(live.EmpWorkSpace, "modules", "foo")
	if loaded.Path != expectedPath {
		t.Fatalf("path not rewritten for local module: %s", loaded.Path)
	}
}

func TestInitModulesLoadsRepoModules(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("module pack only exists for *nix layout")
	}

	findRepoRoot := func(start string) string {
		dir := filepath.Dir(start)
		for {
			if util.IsExist(filepath.Join(dir, "go.mod")) {
				return dir
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				t.Fatalf("go.mod not found from %s", start)
			}
			dir = parent
		}
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("unable to resolve caller path")
	}
	repoRoot := findRepoRoot(thisFile)
	modulesRoot := filepath.Join(repoRoot, "modules")

	configFiles, err := filepath.Glob(filepath.Join(modulesRoot, "*", "config.json"))
	if err != nil {
		t.Fatalf("glob configs: %v", err)
	}
	if len(configFiles) == 0 {
		t.Fatalf("no module configs found under %s", modulesRoot)
	}

	expected := make(map[string]string, len(configFiles))
	for _, cfg := range configFiles {
		modName := filepath.Base(filepath.Dir(cfg))
		expected[modName] = cfg
	}

	tmpWorkspace, err := os.MkdirTemp("", "emp3r0r-modules")
	if err != nil {
		t.Fatalf("temp workspace: %v", err)
	}

	origModules := def.Modules
	origRunners := ModuleRunners
	origModuleDirs := live.ModuleDirs
	origWorkspace := live.EmpWorkSpace

	def.Modules = make(map[string]*def.ModuleConfig, len(origModules))
	for k, v := range origModules {
		def.Modules[k] = v
	}
	ModuleRunners = make(map[string]func(), len(origRunners))
	for k, v := range origRunners {
		ModuleRunners[k] = v
	}
	live.ModuleDirs = []string{modulesRoot}
	live.EmpWorkSpace = tmpWorkspace

	defer func() {
		def.Modules = origModules
		ModuleRunners = origRunners
		live.ModuleDirs = origModuleDirs
		live.EmpWorkSpace = origWorkspace
		_ = os.RemoveAll(tmpWorkspace)
	}()

	InitModules()

	for modName := range expected {
		mod, ok := def.Modules[modName]
		if !ok {
			t.Fatalf("module %s not loaded", modName)
		}
		if _, ok := ModuleRunners[modName]; !ok {
			t.Fatalf("runner not registered for %s", modName)
		}

		expectedPath := filepath.Join(modulesRoot, modName)
		if mod.IsLocal {
			expectedPath = filepath.Join(tmpWorkspace, "modules", modName)
		}
		if mod.Path != expectedPath {
			t.Fatalf("module %s path mismatch: got %s want %s", modName, mod.Path, expectedPath)
		}
		if !util.IsDirExist(mod.Path) {
			t.Fatalf("module path missing on disk for %s: %s", modName, mod.Path)
		}
	}
}

func TestUpdateOptionsAddsDownloadAddr(t *testing.T) {
	modName := "dl_mod"
	def.Modules[modName] = &def.ModuleConfig{
		Name:        modName,
		IsLocal:     false,
		AgentConfig: def.AgentModuleConfig{Exec: "custom"},
	}
	defer delete(def.Modules, modName)

	ModuleRunners[modName] = func() {}
	defer delete(ModuleRunners, modName)

	live.ActiveModule = &def.ModuleConfig{Name: modName, Options: def.ModOptions{}}
	if !UpdateOptions(modName) {
		t.Fatalf("expected module to exist")
	}
	if _, ok := live.ActiveModule.Options["download_addr"]; !ok {
		t.Fatalf("download_addr not injected")
	}

	if UpdateOptions("missing") {
		t.Fatalf("expected missing module to return false")
	}
}
