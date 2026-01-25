package modules

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jm33-m0/arc/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
)

func TestDownloadAndVerifyModuleError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific test")
	}
	_, err := downloadAndVerifyModule("does-not-exist", "bad", "")
	if err == nil {
		t.Fatalf("expected error for missing file and download failure")
	}
}

func TestDownloadAndVerifyModuleSuccessLocal(t *testing.T) {
	data := []byte("hello-downloader")
	file := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	checksum := crypto.SHA256SumRaw(data)

	got, err := downloadAndVerifyModule(file, checksum, "")
	if err != nil {
		t.Fatalf("downloadAndVerifyModule: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("data mismatch: got %q want %q", string(got), string(data))
	}
}

func createTestModule(t *testing.T, content []byte) (path, checksum string) {
	// 1. Compress content (as if it was downloaded)
	compressed, err := arc.CompressXz(content)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}

	// 2. Write to temp file
	tmpFile := filepath.Join(t.TempDir(), "mod.tar.xz")
	if err := os.WriteFile(tmpFile, compressed, 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}

	// 3. Calc checksum of the *compressed* data
	checksum = crypto.SHA256SumRaw(compressed)
	return tmpFile, checksum
}

func TestModuleHandler_Bash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Bash is unix-specific")
	}
	def.DefaultShell = "/bin/bash" // Ensure it is set
	if _, err := os.Stat(def.DefaultShell); err != nil {
		t.Skipf("shell %s not found", def.DefaultShell)
	}

	script := "echo 'hello bash'"
	path, checksum := createTestModule(t, []byte(script))

	inv := def.ResolvedInvocation{
		Argv: []string{}, // Stdin is used, no extra args needed for shell
	}

	out := ModuleHandler("", path, "bash", "test_bash", checksum, inv)
	if !strings.Contains(out, "hello bash") {
		t.Errorf("bash output mismatch: got %q", out)
	}
}

func TestModuleHandler_Python(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Python paths tricky on Windows in this test")
	}
	py3, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found")
	}

	// Setup 'python' symlink in PATH
	binDir := filepath.Join(t.TempDir(), "bin")
	os.MkdirAll(binDir, 0755)
	os.Symlink(py3, filepath.Join(binDir, "python"))
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", binDir+":"+oldPath)
	defer os.Setenv("PATH", oldPath)

	script := "import sys; print('hello python')"
	path, checksum := createTestModule(t, []byte(script))

	inv := def.ResolvedInvocation{
		Argv: []string{}, // Python reads from stdin by default if no file is given
	}

	out := ModuleHandler("", path, "python", "test_python", checksum, inv)
	if !strings.Contains(out, "hello python") {
		t.Errorf("python output mismatch: got %q", out)
	}
}
