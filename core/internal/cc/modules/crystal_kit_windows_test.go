//go:build windows && amd64

package modules

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	agentmodules "github.com/jm33-m0/emp3r0r/core/internal/agent/modules"
)

// crystalKitConfigPath resolves core/modules/Crystal-Kit/config.json relative
// to this test file.
func crystalKitConfigPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(modulesRootFromTest(t), "Crystal-Kit", "config.json")
}

// crystalKitDLLPath resolves the CrystalKit.x64.dll module payload. The DLL is
// a gitignored build artifact produced by make_all.sh.
func crystalKitDLLPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(modulesRootFromTest(t), "Crystal-Kit", "CrystalKit.x64.dll")
}

// crystalKitPICOPath resolves the benign PICO fixture used by the lifecycle
// test. Generate it with core/modules/Crystal-Kit/generate-test-pico.sh.
func crystalKitPICOPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(modulesRootFromTest(t), "Crystal-Kit", "testdata", "noop.pico.bin")
}

// crystalKitCapturePICOPath resolves the args-capturing PICO fixture. Its
// DllMain writes the lpReserved argument to the file named by CK_ARGS_OUT.
func crystalKitCapturePICOPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(modulesRootFromTest(t), "Crystal-Kit", "testdata", "capture.pico.bin")
}

// crystalKitCaptureBakedPICOPath resolves the args-capturing PICO fixture with
// the args baked into the dll_args section at link time ("baked args test").
func crystalKitCaptureBakedPICOPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(modulesRootFromTest(t), "Crystal-Kit", "testdata", "capture_baked.pico.bin")
}

// TestCrystalKitInvocationParsing verifies that operator input such as
//
//	crystal_kit --file C:/pico.bin --args "/arg1 /arg2"
//
// resolves into the correct DLL-module invocation: the file parameter becomes
// DllFileValue, and args is packed as a single BOF z-string arg.
func TestCrystalKitInvocationParsing(t *testing.T) {
	configs, err := readModConfigs(crystalKitConfigPath(t))
	if err != nil {
		t.Fatalf("readModConfigs: %v", err)
	}

	// The suite must expose both the agent-side PICO runner and the C2-side
	// DLL->PICO converter.
	pack := findConfig(t, configs, "crystal_pack")
	if !pack.IsLocal || pack.Build != "bash ./build.sh" {
		t.Fatalf("crystal_pack should be a local module running build.sh, got IsLocal=%v Build=%q", pack.IsLocal, pack.Build)
	}

	config := findConfig(t, configs, "crystal_kit")

	flags := map[string]string{
		"file": `C:/payload.pico.bin`,
		"args": `/arg1 /arg2`,
	}
	invocation, err := resolveInvocation(config, flags)
	if err != nil {
		t.Fatalf("resolveInvocation: %v", err)
	}

	if invocation.DllFileValue != `C:/payload.pico.bin` {
		t.Fatalf("DllFileValue = %q, want %q", invocation.DllFileValue, `C:/payload.pico.bin`)
	}
	if invocation.DllEntry != "go" {
		t.Fatalf("DllEntry = %q, want %q", invocation.DllEntry, "go")
	}
	if invocation.Coff == nil {
		t.Fatalf("expected a COFF sub-invocation for the DLL module")
	}
	if invocation.Coff.Export != "go" {
		t.Fatalf("Coff.Export = %q, want %q", invocation.Coff.Export, "go")
	}
	if len(invocation.Coff.Args) != 1 {
		t.Fatalf("Coff.Args length = %d, want 1", len(invocation.Coff.Args))
	}
	arg := invocation.Coff.Args[0]
	if arg.WireType != "z" {
		t.Fatalf("args wire type = %q, want %q", arg.WireType, "z")
	}
	if arg.Value != `/arg1 /arg2` {
		t.Fatalf("args value = %v, want %q", arg.Value, `/arg1 /arg2`)
	}
}

// TestCrystalKitFullLifecycle runs a benign Crystal Palace PICO through the
// real module pipeline: config parsing, invocation resolution, C2-side
// compression, agent download/verify/decompress, in-memory DLL load, PICO
// execution and DLL unload. The PICO's DllMain is a no-op that returns TRUE,
// so the process must survive the round trip.
func TestCrystalKitFullLifecycle(t *testing.T) {
	skipUnderRace(t)

	dll := readOrSkip(t, crystalKitDLLPath(t))
	pico := readOrSkip(t, crystalKitPICOPath(t))

	// Write the PICO to a temp file so invocation.DllFileValue is a real
	// agent-local path, exactly as it would be after upload.
	picoFile := filepath.Join(t.TempDir(), "payload.pico.bin")
	if err := os.WriteFile(picoFile, pico, 0o600); err != nil {
		t.Fatalf("write PICO fixture: %v", err)
	}

	configs, err := readModConfigs(crystalKitConfigPath(t))
	if err != nil {
		t.Fatalf("readModConfigs: %v", err)
	}
	config := findConfig(t, configs, "crystal_kit")
	config.Path = filepath.Dir(crystalKitConfigPath(t))

	flags := map[string]string{
		"file": picoFile,
		"args": `/arg1 /arg2`,
	}
	invocation, err := resolveInvocation(config, flags)
	if err != nil {
		t.Fatalf("resolveInvocation: %v", err)
	}

	// The C2 hosts CrystalKit.x64.dll as crystal_kit.amd64.gz; the agent
	// downloads/decompresses it into payload_data and uses it as the loader.
	compressedPath, checksum := hostBOFFile(t, dll)

	out := agentmodules.ModuleHandler("", compressedPath, "dll", "crystal_kit", checksum, invocation)
	t.Logf("crystal_kit output: %q", out)

	lower := strings.ToLower(out)
	if strings.Contains(lower, "panic") || strings.Contains(lower, "exception") {
		t.Fatalf("module execution crashed: %q", out)
	}
	if strings.Contains(lower, "unknown payload type") {
		t.Fatalf("dll payload type not dispatched: %q", out)
	}
}

// TestCrystalKitArgsDelivery verifies the full runtime argument path: the
// operator's --args value is packed by the C2, unpacked by the PICO runner
// DLL, handed to go() and finally delivered to DllMain via lpReserved.
func TestCrystalKitArgsDelivery(t *testing.T) {
	skipUnderRace(t)

	dll := readOrSkip(t, crystalKitDLLPath(t))
	pico := readOrSkip(t, crystalKitCapturePICOPath(t))

	picoFile := filepath.Join(t.TempDir(), "capture.pico.bin")
	if err := os.WriteFile(picoFile, pico, 0o600); err != nil {
		t.Fatalf("write PICO fixture: %v", err)
	}

	argsOut := filepath.Join(t.TempDir(), "args.txt")
	if err := os.Setenv("CK_ARGS_OUT", argsOut); err != nil {
		t.Fatalf("set CK_ARGS_OUT: %v", err)
	}
	defer os.Unsetenv("CK_ARGS_OUT")

	configs, err := readModConfigs(crystalKitConfigPath(t))
	if err != nil {
		t.Fatalf("readModConfigs: %v", err)
	}
	config := findConfig(t, configs, "crystal_kit")
	config.Path = filepath.Dir(crystalKitConfigPath(t))

	const args = `/arg1 /arg2`
	invocation, err := resolveInvocation(config, map[string]string{
		"file": picoFile,
		"args": args,
	})
	if err != nil {
		t.Fatalf("resolveInvocation: %v", err)
	}

	compressedPath, checksum := hostBOFFile(t, dll)
	out := agentmodules.ModuleHandler("", compressedPath, "dll", "crystal_kit", checksum, invocation)
	t.Logf("crystal_kit output: %q", out)

	data, err := os.ReadFile(argsOut)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	if string(data) != args {
		t.Fatalf("captured args = %q, want %q", string(data), args)
	}
}

// TestCrystalKitBakedArgsDelivery verifies the baked-args fallback: when the
// operator does not pass --args at runtime, the PICO's dll_args section is
// delivered to DllMain via lpReserved instead.
func TestCrystalKitBakedArgsDelivery(t *testing.T) {
	skipUnderRace(t)

	dll := readOrSkip(t, crystalKitDLLPath(t))
	pico := readOrSkip(t, crystalKitCaptureBakedPICOPath(t))

	picoFile := filepath.Join(t.TempDir(), "capture_baked.pico.bin")
	if err := os.WriteFile(picoFile, pico, 0o600); err != nil {
		t.Fatalf("write PICO fixture: %v", err)
	}

	argsOut := filepath.Join(t.TempDir(), "args_baked.txt")
	if err := os.Setenv("CK_ARGS_OUT", argsOut); err != nil {
		t.Fatalf("set CK_ARGS_OUT: %v", err)
	}
	defer os.Unsetenv("CK_ARGS_OUT")

	configs, err := readModConfigs(crystalKitConfigPath(t))
	if err != nil {
		t.Fatalf("readModConfigs: %v", err)
	}
	config := findConfig(t, configs, "crystal_kit")
	config.Path = filepath.Dir(crystalKitConfigPath(t))

	invocation, err := resolveInvocation(config, map[string]string{"file": picoFile})
	if err != nil {
		t.Fatalf("resolveInvocation: %v", err)
	}

	compressedPath, checksum := hostBOFFile(t, dll)
	out := agentmodules.ModuleHandler("", compressedPath, "dll", "crystal_kit", checksum, invocation)
	t.Logf("crystal_kit output: %q", out)

	data, err := os.ReadFile(argsOut)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	const want = "baked args test"
	if string(data) != want {
		t.Fatalf("captured baked args = %q, want %q", string(data), want)
	}
}

// TestCrystalKitPackAndRunWorkflow exercises the complete crystal-kit flow:
// compile a command-exec post-ex DLL, pack it into PICO with crystal_pack
// (build.sh), run the PICO through crystal_kit with runtime args, and verify
// the command (ipconfig /all) actually executed with those args.
//
// Crystal Palace links DLLs (not raw EXEs), so the packed PE is a small
// CRT-free DLL that runs `cmd.exe /c <args>` and writes the output to the
// file named by CK_EXEC_OUT.
func TestCrystalKitPackAndRunWorkflow(t *testing.T) {
	skipUnderRace(t)

	kitDir := filepath.Join(modulesRootFromTest(t), "Crystal-Kit")

	// 1. Compile the command-exec post-ex DLL.
	gcc, err := exec.LookPath("x86_64-w64-mingw32-gcc")
	if err != nil {
		t.Skipf("skipping: x86_64-w64-mingw32-gcc not found: %v", err)
	}
	dllPath := filepath.Join(t.TempDir(), "cmdexec.x64.dll")
	src := filepath.Join(kitDir, "testdata", "cmdexec.c")
	if out, err := exec.Command(gcc, "-shared", "-O2", "-Wall", src, "-o", dllPath).CombinedOutput(); err != nil {
		t.Fatalf("compile cmdexec.dll: %v\n%s", err, out)
	}

	// 2. Pack it into PICO via crystal_pack's build.sh.
	crystalJar := filepath.Join(kitDir, "crystalpalace", "crystalpalace.jar")
	if _, err := os.Stat(crystalJar); err != nil {
		t.Skipf("skipping: crystalpalace.jar not found: %v", err)
	}
	java, err := exec.LookPath("java")
	if err != nil {
		t.Skipf("skipping: java not found: %v", err)
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("skipping: bash not found: %v", err)
	}

	picoPath := filepath.Join(t.TempDir(), "cmdexec.pico.bin")
	pack := exec.Command(bash, "build.sh", "--dll", dllPath, "--output", picoPath)
	pack.Dir = kitDir
	pack.Env = append(os.Environ(), "JAVA="+java)
	if out, err := pack.CombinedOutput(); err != nil {
		t.Fatalf("crystal_pack (build.sh) failed: %v\n%s", err, out)
	}
	pico, err := os.ReadFile(picoPath)
	if err != nil {
		t.Fatalf("read packed PICO: %v", err)
	}

	// 3. Run the PICO through crystal_kit with runtime args `ipconfig /all`.
	dll := readOrSkip(t, crystalKitDLLPath(t))
	picoFile := filepath.Join(t.TempDir(), "cmdexec.pico.bin")
	if err := os.WriteFile(picoFile, pico, 0o600); err != nil {
		t.Fatalf("write packed PICO: %v", err)
	}

	configs, err := readModConfigs(crystalKitConfigPath(t))
	if err != nil {
		t.Fatalf("readModConfigs: %v", err)
	}
	config := findConfig(t, configs, "crystal_kit")
	config.Path = kitDir

	invocation, err := resolveInvocation(config, map[string]string{
		"file": picoFile,
		"args": "ipconfig /all",
	})
	if err != nil {
		t.Fatalf("resolveInvocation: %v", err)
	}

	compressedPath, checksum := hostBOFFile(t, dll)
	out := agentmodules.ModuleHandler("", compressedPath, "dll", "crystal_kit", checksum, invocation)
	t.Logf("crystal_kit output:\n%s", out)

	if !strings.Contains(out, "Windows IP Configuration") {
		t.Fatalf("ipconfig /all output missing expected marker; got:\n%s", out)
	}
}

// TestCrystalKitCrashContained feeds an invalid PICO (INT3s) through the same
// pipeline. The VEH crash gate in the DLL loader must convert the native
// exception into a recovered Go error instead of killing the test process.
func TestCrystalKitCrashContained(t *testing.T) {
	skipUnderRace(t)

	dll := readOrSkip(t, crystalKitDLLPath(t))
	// 0xCC is INT3; jumping to it raises EXCEPTION_BREAKPOINT, a fatal native
	// exception that the VEH guard must contain.
	badPICO := []byte{0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC}

	picoFile := filepath.Join(t.TempDir(), "bad.pico.bin")
	if err := os.WriteFile(picoFile, badPICO, 0o600); err != nil {
		t.Fatalf("write bad PICO: %v", err)
	}

	configs, err := readModConfigs(crystalKitConfigPath(t))
	if err != nil {
		t.Fatalf("readModConfigs: %v", err)
	}
	config := findConfig(t, configs, "crystal_kit")
	config.Path = filepath.Dir(crystalKitConfigPath(t))

	invocation, err := resolveInvocation(config, map[string]string{"file": picoFile})
	if err != nil {
		t.Fatalf("resolveInvocation: %v", err)
	}

	compressedPath, checksum := hostBOFFile(t, dll)
	out := agentmodules.ModuleHandler("", compressedPath, "dll", "crystal_kit", checksum, invocation)
	t.Logf("crash containment output: %q", out)

	lower := strings.ToLower(out)
	if !strings.Contains(lower, "panic") && !strings.Contains(lower, "exception") {
		t.Fatalf("expected a recovered native exception, got: %q", out)
	}
}
