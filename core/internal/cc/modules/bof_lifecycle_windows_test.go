//go:build windows && amd64

package modules

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	agentmodules "github.com/jm33-m0/emp3r0r/core/internal/agent/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// modulesRootFromTest resolves the <repo>/core/modules directory relative to
// this test file (core/internal/cc/modules).
func modulesRootFromTest(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve caller path")
	}
	return filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))), "modules")
}

// readOrSkip reads a fixture and skips the test when it is missing. The
// COFFLoader DLL and BOF object files are gitignored build artifacts.
func readOrSkip(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("skipping: fixture %s not found: %v", path, err)
	}
	return data
}

// findConfig returns the module config with the given name from a parsed list.
func findConfig(t *testing.T, configs []*def.ModuleConfig, name string) *def.ModuleConfig {
	t.Helper()
	for _, c := range configs {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("module %q not found in config.json", name)
	return nil
}

// hostBOFFile compresses a BOF object file the same way handleInMemoryModule
// does on the C2 side, writes it to a temp file and returns that file's path
// plus the SHA256 checksum of the *compressed* payload.
func hostBOFFile(t *testing.T, bof []byte) (path, checksum string) {
	t.Helper()
	compressed, err := util.Compress(bof)
	if err != nil {
		t.Fatalf("compress BOF: %v", err)
	}
	path = filepath.Join(t.TempDir(), "module.xz")
	if err := os.WriteFile(path, compressed, 0o600); err != nil {
		t.Fatalf("write compressed BOF: %v", err)
	}
	return path, crypto.SHA256SumRaw(compressed)
}

// cacheCoffLoaderDLL seeds the agent memfs with the COFFLoader DLL, matching
// the cache key produced by ModuleHandler's dll branch / fetchDependencyDLL.
func cacheCoffLoaderDLL(t *testing.T, dll []byte) {
	t.Helper()
	if err := util.WriteFileAgent("mem:///coffloader.dll", dll, 0o600); err != nil {
		t.Fatalf("cache COFFLoader DLL in memfs: %v", err)
	}
}

// TestBOFFullLifecycle drives real Windows BOF modules end-to-end:
//
//	config.json parsing -> invocation resolution -> C2-side compression ->
//	agent download + checksum + decompression -> coffloader DLL memmod load ->
//	BOF execution -> captured output
//
// It uses the actual Remote-OPs and Kerbeus-BOF modules and their real
// compiled object files, not mocks.
func TestBOFFullLifecycle(t *testing.T) {
	modulesRoot := modulesRootFromTest(t)

	dllPath := filepath.Join(modulesRoot, "coffloader", "COFFLoader.x64.dll")
	dll := readOrSkip(t, dllPath)

	// Every BOF in this test runs through the cached coffloader DLL
	// (mem:///coffloader.dll). To prove fetchDependencyDLL really uses that
	// cache, evict the hosted .xz and chdir into an empty scratch dir so no
	// download fallback can satisfy the dependency.
	cacheCoffLoaderDLL(t, dll)
	_ = util.RemoveFileAgent("mem:///coffloader.amd64.xz")
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		if err := os.Chdir(origWD); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	}()

	cases := []struct {
		name       string
		configPath string
		moduleName string
		flags      map[string]string
		wantOut    []string
	}{
		{
			name:       "Remote-OPs/get_priv",
			configPath: filepath.Join(modulesRoot, "Remote-OPs", "config.json"),
			moduleName: "remote_ops_get_priv",
			flags:      map[string]string{"privilege": "SeShutdownPrivilege"},
			wantOut:    []string{"SeShutdownPrivilege"},
		},
		{
			name:       "Remote-OPs/process-list-handles",
			configPath: filepath.Join(modulesRoot, "Remote-OPs", "config.json"),
			moduleName: "remote_ops_process-list-handles",
			flags:      map[string]string{"pid": strconv.Itoa(os.Getpid())},
			wantOut:    []string{"Listing handles for PID"},
		},
		{
			name:       "Kerbeus-BOF/klist",
			configPath: filepath.Join(modulesRoot, "Kerbeus-BOF", "config.json"),
			moduleName: "kerbeus_klist",
			flags:      map[string]string{},
			wantOut:    []string{"List Kerberos Tickets", "Cached tickets"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Parse the real module config.json (C2-side parser).
			configs, err := readModConfigs(tc.configPath)
			if err != nil {
				t.Fatalf("readModConfigs(%s): %v", tc.configPath, err)
			}
			config := findConfig(t, configs, tc.moduleName)

			// InitModules normally rewrites Path to the module directory.
			config.Path = filepath.Dir(tc.configPath)

			// 2. Resolve the invocation from the module options (C2-side).
			invocation, err := resolveInvocation(config, tc.flags)
			if err != nil {
				t.Fatalf("resolveInvocation(%s): %v", tc.moduleName, err)
			}
			if invocation.Coff == nil || invocation.Coff.Export == "" {
				t.Fatalf("%s did not resolve a COFF invocation", tc.moduleName)
			}

			// 3. Locate and read the real BOF object file.
			if len(config.AgentConfig.Files) == 0 {
				t.Fatalf("%s has no agent files", tc.moduleName)
			}
			bofPath := filepath.Join(config.Path, config.AgentConfig.Files[0])
			bof := readOrSkip(t, bofPath)

			// 4. Compress the BOF like handleInMemoryModule and run the whole
			//    agent-side ModuleHandler pipeline (download/verify/decompress/
			//    cached-coffloader memmod-load/BOF execution).
			compressedPath, checksum := hostBOFFile(t, bof)
			out := agentmodules.ModuleHandler("", compressedPath, "coff", tc.moduleName, checksum, invocation)

			t.Logf("BOF output:\n%s", out)
			if strings.TrimSpace(out) == "" {
				t.Fatalf("%s produced no output", tc.moduleName)
			}
			for _, want := range tc.wantOut {
				if !strings.Contains(out, want) {
					t.Errorf("%s output missing %q", tc.moduleName, want)
				}
			}
		})
	}
}

// TestBOFDependencyDownloadLifecycle exercises the fallback path where the
// COFFLoader DLL is not yet cached in memfs and must be downloaded from the C2
// file endpoint as <name>.<arch>.xz, decompressed and cached before the BOF
// runs.
func TestBOFDependencyDownloadLifecycle(t *testing.T) {
	modulesRoot := modulesRootFromTest(t)
	dll := readOrSkip(t, filepath.Join(modulesRoot, "coffloader", "COFFLoader.x64.dll"))
	bof := readOrSkip(t, filepath.Join(modulesRoot, "Remote-OPs", "src", "Remote", "get_priv", "get_priv.x64.o"))

	configs, err := readModConfigs(filepath.Join(modulesRoot, "Remote-OPs", "config.json"))
	if err != nil {
		t.Fatalf("readModConfigs: %v", err)
	}
	config := findConfig(t, configs, "remote_ops_get_priv")
	config.Path = filepath.Dir(filepath.Join(modulesRoot, "Remote-OPs", "config.json"))
	invocation, err := resolveInvocation(config, map[string]string{"privilege": "SeShutdownPrivilege"})
	if err != nil {
		t.Fatalf("resolveInvocation: %v", err)
	}

	// Build the hosted <name>.<arch>.xz dependency and place it in a scratch
	// working directory. fetchDependencyDLL asks FetchFile for
	// "coffloader.amd64.xz", which resolves against the process CWD.
	compressedDLL, err := util.Compress(dll)
	if err != nil {
		t.Fatalf("compress DLL: %v", err)
	}
	scratch := t.TempDir()
	if err := os.WriteFile(filepath.Join(scratch, "coffloader.amd64.xz"), compressedDLL, 0o600); err != nil {
		t.Fatalf("write hosted DLL: %v", err)
	}

	// Force a clean dependency state: no memfs cache for either the .dll or
	// the .xz, then run with the scratch directory as CWD.
	_ = util.RemoveFileAgent("mem:///coffloader.dll")
	_ = util.RemoveFileAgent("mem:///coffloader.amd64.xz")

	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(scratch); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		if err := os.Chdir(origWD); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	}()

	compressedPath, checksum := hostBOFFile(t, bof)
	out := agentmodules.ModuleHandler("", compressedPath, "coff", "remote_ops_get_priv", checksum, invocation)
	t.Logf("BOF output:\n%s", out)
	if !strings.Contains(out, "SeShutdownPrivilege") {
		t.Fatalf("BOF output missing privilege name: %q", out)
	}

	// The dependency must now be cached for future BOF runs.
	if cached, err := util.ReadFileAgent("mem:///coffloader.dll"); err != nil || len(cached) == 0 {
		t.Fatalf("coffloader DLL was not cached after download: %v", err)
	}
}

// buildCrashBOF compiles a deliberately crashing BOF object file and returns
// its path. It is skipped (with a clear message) when mingw is unavailable.
func buildCrashBOF(t *testing.T) string {
	t.Helper()
	gcc, err := exec.LookPath("x86_64-w64-mingw32-gcc")
	if err != nil {
		t.Skip("x86_64-w64-mingw32-gcc not found; cannot build crashing BOF fixture")
	}

	src := `void go(char *args, int len) {
	volatile int *p = (volatile int*)0;
	*p = 0xdead;
}
`
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "crash.c")
	objPath := filepath.Join(dir, "crash.x64.o")
	if err := os.WriteFile(srcPath, []byte(src), 0o600); err != nil {
		t.Fatalf("write crash BOF source: %v", err)
	}
	cmd := exec.Command(gcc, "-c", srcPath, "-o", objPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("failed to build crashing BOF: %v\n%s", err, out)
	}
	return objPath
}

// TestBOFCrashIsContained runs a BOF that dereferences a NULL pointer through
// the complete module pipeline. The VEH crash guard must convert the native
// access violation into a Go error instead of killing the test process.
func TestBOFCrashIsContained(t *testing.T) {
	modulesRoot := modulesRootFromTest(t)
	dll := readOrSkip(t, filepath.Join(modulesRoot, "coffloader", "COFFLoader.x64.dll"))
	crashBOF := readOrSkip(t, buildCrashBOF(t))

	configs, err := readModConfigs(filepath.Join(modulesRoot, "Remote-OPs", "config.json"))
	if err != nil {
		t.Fatalf("readModConfigs: %v", err)
	}
	config := findConfig(t, configs, "remote_ops_get_priv")
	config.Path = filepath.Dir(filepath.Join(modulesRoot, "Remote-OPs", "config.json"))
	invocation, err := resolveInvocation(config, map[string]string{"privilege": "SeShutdownPrivilege"})
	if err != nil {
		t.Fatalf("resolveInvocation: %v", err)
	}

	cacheCoffLoaderDLL(t, dll)
	compressedPath, checksum := hostBOFFile(t, crashBOF)
	out := agentmodules.ModuleHandler("", compressedPath, "coff", "crash_bof", checksum, invocation)

	t.Logf("crash containment output: %q", out)
	if out == "" {
		t.Fatalf("expected a recovered error string, got empty output")
	}
	// The panic must have been recovered and reported, not propagated to the
	// test process.
	if !strings.Contains(strings.ToLower(out), "panic") && !strings.Contains(strings.ToLower(out), "exception") {
		t.Errorf("expected panic/exception in output, got: %q", out)
	}
}

// TestBOFLifecycleErrorResilience verifies that failures at every stage of the
// lifecycle return errors to the operator instead of crashing the process.
func TestBOFLifecycleErrorResilience(t *testing.T) {
	modulesRoot := modulesRootFromTest(t)
	dll := readOrSkip(t, filepath.Join(modulesRoot, "coffloader", "COFFLoader.x64.dll"))
	bof := readOrSkip(t, filepath.Join(modulesRoot, "Remote-OPs", "src", "Remote", "get_priv", "get_priv.x64.o"))

	configs, err := readModConfigs(filepath.Join(modulesRoot, "Remote-OPs", "config.json"))
	if err != nil {
		t.Fatalf("readModConfigs: %v", err)
	}
	config := findConfig(t, configs, "remote_ops_get_priv")
	config.Path = filepath.Dir(filepath.Join(modulesRoot, "Remote-OPs", "config.json"))
	invocation, err := resolveInvocation(config, map[string]string{"privilege": "SeShutdownPrivilege"})
	if err != nil {
		t.Fatalf("resolveInvocation: %v", err)
	}

	t.Run("bad checksum", func(t *testing.T) {
		compressedPath, _ := hostBOFFile(t, bof)
		out := agentmodules.ModuleHandler("", compressedPath, "coff", "remote_ops_get_priv", "deadbeef", invocation)
		if out == "" {
			t.Fatalf("expected an error string for a bad checksum")
		}
		if !strings.Contains(strings.ToLower(out), "checksum") {
			t.Errorf("expected checksum error, got: %q", out)
		}
	})

	t.Run("empty BOF payload", func(t *testing.T) {
		cacheCoffLoaderDLL(t, dll)
		compressedPath, checksum := hostBOFFile(t, []byte{})
		out := agentmodules.ModuleHandler("", compressedPath, "coff", "remote_ops_get_priv", checksum, invocation)
		if out == "" {
			t.Fatalf("expected an error string for an empty BOF")
		}
		if !strings.Contains(strings.ToLower(out), "empty") {
			t.Errorf("expected empty-payload error, got: %q", out)
		}
	})

	t.Run("malformed COFF object", func(t *testing.T) {
		cacheCoffLoaderDLL(t, dll)
		// Valid gzip but garbage COFF bytes: the DLL loader must reject it
		// (or contain any native fault) without killing the test process.
		compressedPath, checksum := hostBOFFile(t, []byte("this is definitely not a COFF object"))
		out := agentmodules.ModuleHandler("", compressedPath, "coff", "remote_ops_get_priv", checksum, invocation)
		if out == "" {
			t.Fatalf("expected an error string for a malformed COFF object")
		}
	})

	t.Run("missing coffloader dependency", func(t *testing.T) {
		_ = util.RemoveFileAgent("mem:///coffloader.dll")
		_ = util.RemoveFileAgent("mem:///coffloader.amd64.xz")

		// Point the process CWD at an empty directory so the dependency
		// download has no local file to fall back to. ModuleHandler must
		// surface the failure without crashing.
		origWD, err := os.Getwd()
		if err != nil {
			t.Fatalf("getwd: %v", err)
		}
		if err := os.Chdir(t.TempDir()); err != nil {
			t.Fatalf("chdir: %v", err)
		}
		defer func() {
			if err := os.Chdir(origWD); err != nil {
				t.Errorf("restore cwd: %v", err)
			}
		}()

		compressedPath, checksum := hostBOFFile(t, bof)
		out := agentmodules.ModuleHandler("", compressedPath, "coff", "remote_ops_get_priv", checksum, invocation)
		if out == "" {
			t.Fatalf("expected an error string when the coffloader dependency is missing")
		}
	})
}
