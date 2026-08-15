package modules

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func TestReadModConfig(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "emp3r0r-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

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
				{"literal": "test_exec"}
			]
		}
	}`

	configFile := filepath.Join(tmpDir, "config.json")
	err = os.WriteFile(configFile, []byte(jsonConfig), 0o644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := readModCondig(configFile)
	if err != nil {
		t.Fatalf("readModCondig failed: %v", err)
	}

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
	tmpDir, err := os.MkdirTemp("", "emp3r0r-test-partial")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	jsonConfig := `{
		"name": "test_module_partial",
		"parameters": [],
		"invocation": {"argv": []}
	}`

	configFile := filepath.Join(tmpDir, "config.json")
	err = os.WriteFile(configFile, []byte(jsonConfig), 0o644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := readModCondig(configFile)
	if err != nil {
		t.Fatalf("readModCondig failed: %v", err)
	}

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
			CoffExport: "Run",
			Argv: []def.InvocationArg{
				{Literal: "runner"},
				{Flag: "-p", Param: "port"},
			},
			StdinParam: "message",
			Coff: &def.CoffInvocation{
				Export: "Run",
				Args:   []def.CoffArgSpec{{Param: "port"}},
			},
		},
		Options: def.ModOptions{
			"port":    {Name: "port", Val: "8080", Type: "uint", Required: true},
			"message": {Name: "message", Val: "hello", Type: "string"},
		},
	}

	inv, err := resolveInvocation(config, map[string]string{})
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
	if inv.Coff.Args[0].WireType != "i" {
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

	if _, err := resolveInvocation(config, map[string]string{}); err == nil {
		t.Fatalf("expected error for missing required option")
	}
}

func TestResolveInvocationCOFFArgsAlwaysSatisfied(t *testing.T) {
	config := &def.ModuleConfig{
		AgentConfig: def.AgentModuleConfig{Type: "coff"},
		Invocation: def.InvocationSpec{
			Coff: &def.CoffInvocation{
				Export: "go",
				Args: []def.CoffArgSpec{
					{Param: "privilege"},
					{Param: "pid"},
				},
			},
		},
		Options: def.ModOptions{
			"privilege": {Name: "privilege", Type: "cstr", Required: true, Val: ""},
			"pid":       {Name: "pid", Type: "int", Required: false, Val: ""},
		},
	}

	// A missing required string arg and an empty numeric arg must still be
	// packed (as zero values) so the BOF always receives the full arg list.
	inv, err := resolveInvocation(config, map[string]string{})
	if err != nil {
		t.Fatalf("resolveInvocation: %v", err)
	}
	if inv.Coff == nil || len(inv.Coff.Args) != 2 {
		t.Fatalf("expected 2 packed COFF args, got %+v", inv.Coff)
	}
	if inv.Coff.Args[0].WireType != "z" || inv.Coff.Args[0].Value != "" {
		t.Fatalf("privilege arg not satisfied: %+v", inv.Coff.Args[0])
	}
	if inv.Coff.Args[1].WireType != "i" {
		t.Fatalf("pid wire type mismatch: %+v", inv.Coff.Args[1])
	}
	if _, ok := inv.Coff.Args[1].Value.(float64); !ok {
		t.Fatalf("pid arg should be numeric zero, got %T (%v)", inv.Coff.Args[1].Value, inv.Coff.Args[1].Value)
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
				"type": "cstr",
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
				{"literal": "runner"}
			],
			"stdin_param": "flagged",
			"timeout_seconds": 42,
			"coff_export": "Run"
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

func TestUpdateModuleHelp(t *testing.T) {
	modName := "help_mod"
	config := &def.ModuleConfig{
		Name: modName,
		Options: def.ModOptions{
			"foo": {Name: "foo", Desc: "bar"},
		},
	}
	def.Modules.Store(modName, config)
	defer def.Modules.Delete(modName)

	if err := updateModuleHelp(config); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if val, ok := def.Modules.Load(modName); !ok || val.(*def.ModuleConfig).Options["foo"].Desc != "bar" {
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

	origModules := 0
	def.Modules.Range(func(_, _ any) bool {
		origModules++
		return true
	})
	origRunners := ModuleRunners
	origModuleDirs := live.ModuleDirs
	origWorkspace := live.EmpWorkSpace
	ModuleRunners = make(map[string]func(ctx *context.C2Context))
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
		def.Modules.Delete("foo")
		live.ModuleDirs = origModuleDirs
		live.EmpWorkSpace = origWorkspace
	}()

	live.EmpWorkSpace = filepath.Join(tmpRoot, "workspace")
	live.ModuleDirs = []string{moduleDir}

	InitModules()

	count := 0
	def.Modules.Range(func(_, _ any) bool {
		count++
		return true
	})
	if count != origModules+1 {
		t.Fatalf("module not loaded")
	}
	if _, ok := ModuleRunners["foo"]; !ok {
		t.Fatalf("custom runner not registered")
	}
	loadedVal, ok := def.Modules.Load("foo")
	if !ok {
		t.Fatalf("module not stored")
	}
	loaded := loadedVal.(*def.ModuleConfig)
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

	tmpWorkspace, err := os.MkdirTemp("", "emp3r0r-modules")
	if err != nil {
		t.Fatalf("temp workspace: %v", err)
	}

	type expectedMod struct {
		Name         string
		ExpectedPath string
	}
	expected := make(map[string]expectedMod)
	for _, cfg := range configFiles {
		configs, err := readModConfigs(cfg)
		if err != nil {
			t.Fatalf("readModConfigs %s: %v", cfg, err)
		}
		dirName := filepath.Base(filepath.Dir(cfg))
		for _, config := range configs {
			expectedPath := filepath.Dir(cfg)
			if config.IsLocal || config.Build != "" {
				expectedPath = filepath.Join(tmpWorkspace, "modules", dirName)
			}
			expected[config.Name] = expectedMod{
				Name:         config.Name,
				ExpectedPath: expectedPath,
			}
		}
	}

	// Backup def.Modules
	backupModules := make(map[string]*def.ModuleConfig)
	def.Modules.Range(func(key, value any) bool {
		backupModules[key.(string)] = value.(*def.ModuleConfig)
		return true
	})

	origRunners := ModuleRunners
	origModuleDirs := live.ModuleDirs
	origWorkspace := live.EmpWorkSpace

	// Clear def.Modules for test
	def.Modules.Range(func(key, value any) bool {
		def.Modules.Delete(key)
		return true
	})

	ModuleRunners = make(map[string]func(ctx *context.C2Context), len(origRunners))
	for k, v := range origRunners {
		ModuleRunners[k] = v
	}
	live.ModuleDirs = []string{modulesRoot}
	live.EmpWorkSpace = tmpWorkspace

	defer func() {
		// Restore def.Modules
		def.Modules.Range(func(key, value any) bool {
			def.Modules.Delete(key)
			return true
		})
		for k, v := range backupModules {
			def.Modules.Store(k, v)
		}
		ModuleRunners = origRunners
		live.ModuleDirs = origModuleDirs
		live.EmpWorkSpace = origWorkspace
		_ = os.RemoveAll(tmpWorkspace)
	}()

	InitModules()

	for modName, exp := range expected {
		val, ok := def.Modules.Load(modName)
		if !ok {
			t.Fatalf("module %s not loaded", modName)
		}
		mod := val.(*def.ModuleConfig)
		if _, ok := ModuleRunners[modName]; !ok {
			t.Fatalf("runner not registered for %s", modName)
		}

		if mod.Path != exp.ExpectedPath {
			t.Fatalf("module %s path mismatch: got %s want %s", modName, mod.Path, exp.ExpectedPath)
		}
		if !util.IsDirExist(mod.Path) {
			t.Fatalf("module path missing on disk for %s: %s", modName, mod.Path)
		}
	}
}

func TestUpdateOptionsAddsDownloadAddr(t *testing.T) {
	modName := "dl_mod"
	def.Modules.Store(modName, &def.ModuleConfig{
		Name:        modName,
		IsLocal:     false,
		AgentConfig: def.AgentModuleConfig{Exec: "custom"},
	})
	defer def.Modules.Delete(modName)

	ModuleRunners[modName] = func(ctx *context.C2Context) {}
	defer delete(ModuleRunners, modName)

	live.ActiveModule = &def.ModuleConfig{Name: modName, Options: def.ModOptions{}}
	if !UpdateOptions(modName) {
		t.Fatalf("expected module to exist")
	}
	if _, ok := live.ActiveModule.Options["download_addr"]; ok {
		t.Fatalf("download_addr should not be injected")
	}

	if UpdateOptions("missing") {
		t.Fatalf("expected missing module to return false")
	}
}

func TestReadModConfigsMultiple(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "emp3r0r-test-multiple")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	jsonConfig := `[
		{
			"name": "multi_module_1",
			"build": "go build 1",
			"author": "tester",
			"date": "2023-10-27",
			"comment": "A test module 1",
			"is_local": true,
			"platform": "Linux",
			"path": "/tmp/test_module",
			"fileless": false,
			"agent_config": {
				"exec": "exec1",
				"files": ["file1"],
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
					{"literal": "exec1"}
				]
			}
		},
		{
			"name": "multi_module_2",
			"build": "go build 2",
			"author": "tester",
			"date": "2023-10-27",
			"comment": "A test module 2",
			"is_local": false,
			"platform": "Windows",
			"path": "/tmp/test_module",
			"fileless": true,
			"agent_config": {
				"exec": "exec2",
				"files": ["file2"],
				"in_memory": false,
				"type": "coff",
				"interactive": false
			},
			"parameters": [
				{
					"name": "option2",
					"description": "Description 2",
					"default": "value2",
					"choices": ["value2", "value3"],
					"type": "string",
					"required": true
				}
			],
			"invocation": {
				"argv": [
					{"literal": "exec2"}
				]
			}
		}
	]`

	configFile := filepath.Join(tmpDir, "config.json")
	err = os.WriteFile(configFile, []byte(jsonConfig), 0o644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	configs, err := readModConfigs(configFile)
	if err != nil {
		t.Fatalf("readModConfigs failed: %v", err)
	}

	if len(configs) != 2 {
		t.Fatalf("Expected 2 configurations, got %d", len(configs))
	}

	if configs[0].Name != "multi_module_1" {
		t.Errorf("Expected first config Name 'multi_module_1', got '%s'", configs[0].Name)
	}
	if configs[0].Build != "go build 1" {
		t.Errorf("Expected first config Build 'go build 1', got '%s'", configs[0].Build)
	}
	if !configs[0].IsLocal {
		t.Errorf("Expected first config IsLocal true, got false")
	}

	if configs[1].Name != "multi_module_2" {
		t.Errorf("Expected second config Name 'multi_module_2', got '%s'", configs[1].Name)
	}
	if configs[1].Build != "go build 2" {
		t.Errorf("Expected second config Build 'go build 2', got '%s'", configs[1].Build)
	}
	if configs[1].IsLocal {
		t.Errorf("Expected second config IsLocal false, got true")
	}
}

func TestLoadAllModulesConfigs(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("unable to resolve caller path")
	}
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(thisFile))))
	modulesRoot := filepath.Join(repoRoot, "modules")

	configCount := 0
	err := filepath.Walk(modulesRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Name() == "config.json" {
			configs, readErr := readModConfigs(path)
			if readErr != nil {
				t.Errorf("Failed to read config %s: %v", path, readErr)
				return nil
			}
			if len(configs) == 0 {
				t.Errorf("Config file %s produced 0 configurations", path)
				return nil
			}
			for i, c := range configs {
				if c.Name == "" {
					t.Errorf("Config %d in %s has an empty name", i, path)
				}
				configCount++
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to walk modules directory: %v", err)
	}

	if configCount == 0 {
		t.Fatalf("No module configs found in %s", modulesRoot)
	}
	t.Logf("Successfully loaded %d configurations from all config.json files", configCount)
}

func TestReadModConfigUnifiedCOFF(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "emp3r0r-unified-coff")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	unified := `{
		"name": "unified_coff",
		"build": "make",
		"author": "tester",
		"date": "2026-01-01",
		"comment": "unified COFF module",
		"is_local": false,
		"platform": "Linux",
		"fileless": true,
		"agent_config": {
			"exec": "",
			"files": ["unified.o"],
			"in_memory": true,
			"type": "coff",
			"interactive": false
		},
		"parameters": [
			{
				"name": "who",
				"description": "Who to greet",
				"default": "World",
				"type": "cstr",
				"required": false
			},
			{
				"name": "count",
				"description": "How many times",
				"default": "1",
				"type": "int",
				"required": true
			}
		],
		"invocation": {
			"coff_export": "go"
		}
	}`

	cfgFile := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(cfgFile, []byte(unified), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	config, err := readModCondig(cfgFile)
	if err != nil {
		t.Fatalf("readModCondig: %v", err)
	}

	if config.Invocation.CoffExport != "go" {
		t.Fatalf("CoffExport mismatch: %q", config.Invocation.CoffExport)
	}

	if config.Invocation.Coff == nil {
		t.Fatalf("Coff invocation not synthesised")
	}
	if config.Invocation.Coff.Export != "go" {
		t.Fatalf("Coff.Export mismatch: %q", config.Invocation.Coff.Export)
	}
	if len(config.Invocation.Coff.Args) != 2 {
		t.Fatalf("expected 2 COFF args, got %d", len(config.Invocation.Coff.Args))
	}
	if config.Invocation.Coff.Args[0].Param != "who" {
		t.Fatalf("COFF arg[0] mismatch: %+v", config.Invocation.Coff.Args[0])
	}
	if config.Invocation.Coff.Args[1].Param != "count" {
		t.Fatalf("COFF arg[1] mismatch: %+v", config.Invocation.Coff.Args[1])
	}

	paramArgvCount := 0
	for _, a := range config.Invocation.Argv {
		if a.Param != "" {
			paramArgvCount++
		}
	}
	if paramArgvCount != 2 {
		t.Fatalf("expected 2 param-derived argv entries, got %d", paramArgvCount)
	}

	whoOpt := config.Options["who"]
	if whoOpt == nil || whoOpt.Type != "cstr" {
		t.Fatalf("who option type missing: %+v", whoOpt)
	}
	countOpt := config.Options["count"]
	if countOpt == nil || countOpt.Type != "int" {
		t.Fatalf("count option type missing: %+v", countOpt)
	}
}

func TestReadModConfigUnifiedStarlark(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "emp3r0r-unified-star")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	unified := `{
		"name": "unified_star",
		"author": "tester",
		"date": "2026-01-01",
		"comment": "unified starlark module",
		"is_local": false,
		"platform": "Windows",
		"fileless": true,
		"agent_config": {
			"exec": "search.star",
			"files": ["search.star"],
			"in_memory": true,
			"type": "starlark",
			"interactive": false
		},
		"parameters": [
			{
				"name": "filter",
				"description": "LDAP filter",
				"default": "(objectclass=*)",
				"type": "string",
				"required": true
			},
			{
				"name": "scope",
				"description": "Search scope",
				"default": "0",
				"type": "int",
				"required": false
			}
		],
		"invocation": {}
	}`

	cfgFile := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(cfgFile, []byte(unified), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	config, err := readModCondig(cfgFile)
	if err != nil {
		t.Fatalf("readModCondig: %v", err)
	}

	if config.Invocation.Coff != nil {
		t.Fatalf("unexpected Coff invocation for starlark module")
	}

	filterOpt := config.Options["filter"]
	if filterOpt == nil || filterOpt.Type != "string" {
		t.Fatalf("filter option unexpected: %+v", filterOpt)
	}
	scopeOpt := config.Options["scope"]
	if scopeOpt == nil || scopeOpt.Type != "int" {
		t.Fatalf("scope option unexpected: %+v", scopeOpt)
	}
}

func TestReadModConfigUnifiedArgvFlag(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "emp3r0r-unified-flag")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	unified := `{
		"name": "unified_flag",
		"author": "tester",
		"date": "2026-01-01",
		"comment": "unified module with argv_flag",
		"is_local": false,
		"platform": "Linux",
		"fileless": true,
		"agent_config": {
			"exec": "tool",
			"files": ["tool"],
			"in_memory": false,
			"type": "elf",
			"interactive": false
		},
		"parameters": [
			{
				"name": "port",
				"description": "Port number",
				"default": "8080",
				"type": "uint",
				"argv_flag": "-p",
				"required": true
			},
			{
				"name": "host",
				"description": "Target host",
				"default": "localhost",
				"type": "string",
				"argv_flag": "-h",
				"required": false
			}
		],
		"invocation": {
			"argv": [{"literal": "tool"}]
		}
	}`

	cfgFile := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(cfgFile, []byte(unified), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	config, err := readModCondig(cfgFile)
	if err != nil {
		t.Fatalf("readModCondig: %v", err)
	}

	if len(config.Invocation.Argv) != 3 {
		t.Fatalf("expected 3 argv entries, got %d: %+v", len(config.Invocation.Argv), config.Invocation.Argv)
	}
	if config.Invocation.Argv[0].Literal != "tool" {
		t.Fatalf("first argv should be literal 'tool': %+v", config.Invocation.Argv[0])
	}
	if config.Invocation.Argv[1].Flag != "-p" || config.Invocation.Argv[1].Param != "port" {
		t.Fatalf("second argv should be flag -p / param port: %+v", config.Invocation.Argv[1])
	}
	if config.Invocation.Argv[2].Flag != "-h" || config.Invocation.Argv[2].Param != "host" {
		t.Fatalf("third argv should be flag -h / param host: %+v", config.Invocation.Argv[2])
	}

	inv, err := resolveInvocation(config, map[string]string{})
	if err != nil {
		t.Fatalf("resolveInvocation: %v", err)
	}
	expected := []string{"tool", "-p", "8080", "-h", "localhost"}
	if len(inv.Argv) != len(expected) {
		t.Fatalf("resolved argv len mismatch: %v", inv.Argv)
	}
	for i, v := range expected {
		if inv.Argv[i] != v {
			t.Fatalf("argv[%d]: want %q got %q", i, v, inv.Argv[i])
		}
	}
}

func TestReadModConfigDLL(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "emp3r0r-test-dll")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	jsonConfig := `{
		"name": "coffloader",
		"platform": "Windows",
		"agent_config": {
			"exec": "",
			"files": ["COFFLoader.x64.dll"],
			"in_memory": true,
			"type": "dll",
			"interactive": false
		},
		"parameters": [
			{"name": "file", "description": "BOF file to run", "default": "", "type": "string", "required": true},
			{"name": "priv", "description": "Privilege to enable", "default": "SeShutdownPrivilege", "type": "string", "required": false}
		],
		"invocation": {
			"dll_export": "LoadAndRun",
			"dll_entry": "go",
			"dll_file_param": "file"
		},
		"dependencies": ["coffloader"]
	}`

	configFile := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configFile, []byte(jsonConfig), 0o644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := readModCondig(configFile)
	if err != nil {
		t.Fatalf("readModCondig failed: %v", err)
	}

	if !strings.EqualFold(config.AgentConfig.Type, "dll") {
		t.Fatalf("expected type dll, got %s", config.AgentConfig.Type)
	}
	if config.Invocation.DllExport != "LoadAndRun" {
		t.Fatalf("expected DllExport LoadAndRun, got %s", config.Invocation.DllExport)
	}
	if config.Invocation.DllEntry != "go" {
		t.Fatalf("expected DllEntry go, got %s", config.Invocation.DllEntry)
	}
	if config.Invocation.DllFileParam != "file" {
		t.Fatalf("expected DllFileParam file, got %s", config.Invocation.DllFileParam)
	}
	if config.Invocation.Coff == nil {
		t.Fatalf("expected Coff invocation to be populated for DLL module")
	}
	if config.Invocation.Coff.Export != "go" {
		t.Fatalf("expected Coff.Export go, got %s", config.Invocation.Coff.Export)
	}
	if len(config.Invocation.Coff.Args) != 1 {
		t.Fatalf("expected only the priv arg to be packed (file excluded), got %d", len(config.Invocation.Coff.Args))
	}
	if config.Invocation.Coff.Args[0].Param != "priv" {
		t.Fatalf("expected first Coff arg to be priv, got %s", config.Invocation.Coff.Args[0].Param)
	}
	if len(config.Dependencies) != 1 || config.Dependencies[0] != "coffloader" {
		t.Fatalf("unexpected dependencies: %v", config.Dependencies)
	}

	inv, err := resolveInvocation(config, map[string]string{"file": "mem:///get_priv.x64.o", "priv": "SeDebugPrivilege"})
	if err != nil {
		t.Fatalf("resolveInvocation: %v", err)
	}
	if inv.DllFileValue != "mem:///get_priv.x64.o" {
		t.Fatalf("unexpected DllFileValue: %q", inv.DllFileValue)
	}
	if inv.Coff == nil || len(inv.Coff.Args) != 1 || inv.Coff.Args[0].WireType != "z" {
		t.Fatalf("unexpected resolved Coff args: %+v", inv.Coff)
	}
}

func TestReadModConfigWindowsCOFFAutoDependency(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "emp3r0r-test-coff-dep")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	jsonConfig := `{
		"name": "get_priv",
		"platform": "Windows",
		"agent_config": {
			"files": ["get_priv.x64.o"],
			"in_memory": true,
			"type": "coff",
			"interactive": false
		},
		"parameters": [
			{"name": "priv", "description": "Privilege to enable", "default": "", "type": "string", "required": true}
		],
		"invocation": {"coff_export": "go"}
	}`

	configFile := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configFile, []byte(jsonConfig), 0o644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := readModCondig(configFile)
	if err != nil {
		t.Fatalf("readModCondig failed: %v", err)
	}

	found := false
	for _, dep := range config.Dependencies {
		if dep == "coffloader" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected Windows COFF module to auto-depend on coffloader, got %v", config.Dependencies)
	}
}

func TestDLLArchHelpers(t *testing.T) {
	if got := dllArch("COFFLoader.x64.dll"); got != "amd64" {
		t.Fatalf("dllArch x64: got %q", got)
	}
	if got := dllArch("COFFLoader.x86.dll"); got != "386" {
		t.Fatalf("dllArch x86: got %q", got)
	}
	if got := normalizeAgentArch("x64"); got != "amd64" {
		t.Fatalf("normalizeAgentArch x64: got %q", got)
	}
	if got := normalizeAgentArch("x32"); got != "386" {
		t.Fatalf("normalizeAgentArch x32: got %q", got)
	}
	if got := normalizeAgentArch("386"); got != "386" {
		t.Fatalf("normalizeAgentArch 386: got %q", got)
	}
	files := []string{"COFFLoader.x64.dll", "COFFLoader.x86.dll"}
	if got := selectDLLFile(files, "386"); got != "COFFLoader.x86.dll" {
		t.Fatalf("selectDLLFile 386: got %q", got)
	}
	if got := selectDLLFile(files, "amd64"); got != "COFFLoader.x64.dll" {
		t.Fatalf("selectDLLFile amd64: got %q", got)
	}
}
