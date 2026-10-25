package modules

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/paths"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// newInstalledTestLayout creates a realistic installation layout: the
// installed tree lives under <prefix>/lib/emp3r0r with the shipped zig next to
// it, and the operator workspace is a separate directory. It returns the
// installed data dir and the workspace, and restores globals on cleanup.
func newInstalledTestLayout(t *testing.T) (dataDir, workspace string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("module toolchain shims are Linux-only")
	}

	root := t.TempDir()
	dataDir = filepath.Join(root, "usr", "local", "lib", "emp3r0r")
	workspace = filepath.Join(root, "home", "operator", ".emp3r0r")
	for _, dir := range []string{dataDir, workspace} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	zig, err := exec.LookPath("zig")
	if err != nil {
		t.Skip("zig is not available in this environment")
	}
	if zig, err = filepath.Abs(zig); err != nil {
		t.Fatal(err)
	}
	zigDir := filepath.Join(dataDir, "zig")
	if err := os.MkdirAll(zigDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(zig, filepath.Join(zigDir, "zig")); err != nil {
		t.Fatal(err)
	}

	origData, origWS, origWWW := live.EmpDataDir, live.EmpWorkSpace, paths.WWWRoot
	live.EmpDataDir = dataDir
	live.EmpWorkSpace = workspace
	paths.WWWRoot = filepath.Join(workspace, "www")
	t.Cleanup(func() {
		live.EmpDataDir = origData
		live.EmpWorkSpace = origWS
		paths.WWWRoot = origWWW
	})
	return dataDir, workspace
}

func TestModuleToolchainUsesShippedZig(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("module toolchain shims are Linux-only")
	}

	dataDir, workspace := newInstalledTestLayout(t)

	target, err := moduleLinuxTarget()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(target, "linux-gnu.2.17") && !strings.HasSuffix(target, "linux-musl") {
		t.Fatalf("Linux module target %q is not pinned to glibc 2.17 or musl", target)
	}

	binDir, zig, err := ensureModuleToolchain()
	if err != nil {
		t.Fatalf("prepare module toolchain: %v", err)
	}
	wantZig := filepath.Join(dataDir, "zig", "zig")
	if filepath.Clean(zig) != filepath.Clean(wantZig) {
		t.Fatalf("module build used %q, want shipped zig %q", zig, wantZig)
	}
	if !strings.HasPrefix(binDir, workspace+string(os.PathSeparator)) {
		t.Fatalf("module shims are not in the operator workspace: %s", binDir)
	}
	if strings.HasPrefix(binDir, dataDir+string(os.PathSeparator)) {
		t.Fatalf("module shims must not be written into the installed tree: %s", binDir)
	}

	tests := map[string]string{
		"cc":                       shellQuote("-target") + " " + shellQuote(target),
		"clang":                    shellQuote("-target") + " " + shellQuote(target),
		"x86_64-w64-mingw32-gcc":   "x86_64-windows-gnu",
		"x86_64-w64-mingw32-clang": "x86_64-windows-gnu",
		"i686-w64-mingw32-gcc":     "x86-windows-gnu",
		"i686-w64-mingw32-clang":   "x86-windows-gnu",
	}
	for name, want := range tests {
		path := filepath.Join(binDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read shim %s: %v", name, err)
		}
		if !strings.Contains(string(data), want) {
			t.Errorf("shim %s does not contain %q:\n%s", name, want, data)
		}
	}

	// The shims must actually be executable and resolve through zig.
	out, err := exec.Command(filepath.Join(binDir, "cc"), "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("run cc shim: %v\n%s", err, out)
	}
	if !strings.Contains(strings.ToLower(string(out)), "zig") {
		t.Fatalf("cc shim did not invoke zig:\n%s", out)
	}

	originalPath := os.Getenv("PATH")
	env, err := moduleBuildEnv()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("PATH") != originalPath {
		t.Fatal("moduleBuildEnv modified the process PATH")
	}
	envMap := make(map[string]string, len(env))
	for _, kv := range env {
		key, value, ok := strings.Cut(kv, "=")
		if ok {
			envMap[key] = value
		}
	}
	if !strings.HasPrefix(envMap["PATH"], binDir) {
		t.Fatalf("module PATH does not start with the zig shims: %s", envMap["PATH"])
	}
	for key, want := range map[string]string{
		"CC":     filepath.Join(binDir, "cc"),
		"CXX":    filepath.Join(binDir, "c++"),
		"AR":     filepath.Join(binDir, "ar"),
		"RANLIB": filepath.Join(binDir, "ranlib"),
		"ZIG":    zig,
	} {
		if envMap[key] != want {
			t.Errorf("%s = %q, want %q", key, envMap[key], want)
		}
	}
}

func TestBuildMakeAllBuildsBothWindowsArchesWithZig(t *testing.T) {
	dataDir, workspace := newInstalledTestLayout(t)
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })

	// Put the suite where an installation keeps its modules. It has a
	// make_all.sh but no build command, so it must be copied to the workspace
	// and compiled there.
	installModules := filepath.Join(dataDir, "modules")
	modDir := filepath.Join(installModules, "BOF-Suite")
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"config.json": `{
	"name": "bof_suite",
	"comment": "on-demand BOF suite",
	"platform": "Windows",
	"agent_config": {"exec": "", "type": "coff", "files": ["payload.x64.o", "payload.x86.o"]},
	"invocation": {"coff_export": "go"}
}`,
		"payload.c": "int payload(void) { return 1; }\n",
		"make_all.sh": `#!/bin/bash
set -e
make -j2
`,
		"Makefile": `all: payload.x64.o payload.x86.o
payload.x64.o: payload.c
	x86_64-w64-mingw32-clang -c payload.c -o $@
	x86_64-w64-mingw32-strip --strip-unneeded $@
payload.x86.o: payload.c
	i686-w64-mingw32-clang -c payload.c -o $@
	i686-w64-mingw32-strip --strip-unneeded $@
`,
	}
	for name, content := range files {
		mode := os.FileMode(0o644)
		if name == "make_all.sh" {
			mode = 0o755
		}
		if err := os.WriteFile(filepath.Join(modDir, name), []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}

	origDirs := live.ModuleDirs
	t.Cleanup(func() { live.ModuleDirs = origDirs })
	live.ModuleDirs = []string{installModules, filepath.Join(workspace, "modules")}
	def.Modules.Delete("bof_suite")
	deleteModuleRunner("bof_suite")
	t.Cleanup(func() {
		def.Modules.Delete("bof_suite")
		deleteModuleRunner("bof_suite")
	})

	InitModules()
	val, ok := def.Modules.Load("bof_suite")
	if !ok {
		t.Fatal("bof_suite was not loaded from the installation")
	}
	config := val.(*def.ModuleConfig)
	wsModDir := filepath.Join(workspace, "modules", "BOF-Suite")
	if config.Path != wsModDir {
		t.Fatalf("suite path = %q, want workspace copy %q", config.Path, wsModDir)
	}
	if !moduleFilesMissing(config) {
		t.Fatal("missing payloads were not detected")
	}
	if _, err := os.Stat(filepath.Join(modDir, "payload.x64.o")); !os.IsNotExist(err) {
		t.Fatalf("installation tree already has a built payload: %v", err)
	}

	if _, err := build_make_all(config); err != nil {
		t.Fatalf("build make_all: %v", err)
	}

	wantMachine := map[string]uint16{"payload.x64.o": 0x8664, "payload.x86.o": 0x014c}
	for file, want := range wantMachine {
		data, err := os.ReadFile(filepath.Join(wsModDir, file))
		if err != nil {
			t.Fatalf("read workspace %s: %v", file, err)
		}
		if len(data) < 2 {
			t.Fatalf("%s is too short to be COFF", file)
		}
		if got := binary.LittleEndian.Uint16(data[:2]); got != want {
			t.Fatalf("%s COFF machine = %#x, want %#x", file, got, want)
		}
		if _, err := os.Stat(filepath.Join(modDir, file)); !os.IsNotExist(err) {
			t.Fatalf("build wrote %s into the installed tree", file)
		}
	}

	binDir := filepath.Join(workspace, moduleToolchainSubdir, "bin")
	if !strings.HasPrefix(binDir, workspace+string(os.PathSeparator)) {
		t.Fatalf("module shims escaped the workspace: %s", binDir)
	}
}
