//go:build windows && amd64

package modules

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// stagedLoaderRequireTools skips the build test when the MinGW-w64 toolchain
// and nasm are not on PATH (the msys2 module-integration CI step has them).
func stagedLoaderRequireTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"bash", "x86_64-w64-mingw32-gcc", "cc", "nasm"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("skipping: %s not found in PATH", tool)
		}
	}
}

// stagedLoaderBuild runs build.sh with the given extra flags and fails the
// test on error. scPath/out are the required --shellcode/--output values.
func stagedLoaderBuild(t *testing.T, dir, scPath, out string, extra ...string) {
	t.Helper()
	args := append([]string{"./build.sh", "--shellcode", scPath, "--output", out, "--arch", "x64"}, extra...)
	cmd := exec.Command("bash", args...)
	cmd.Dir = dir
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build.sh %v failed: %v\n%s", extra, err, o)
	}
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
