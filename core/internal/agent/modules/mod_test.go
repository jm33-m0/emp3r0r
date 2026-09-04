package modules

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
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
	compressed, err := util.Compress(content)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}

	// 2. Write to temp file
	tmpFile := filepath.Join(t.TempDir(), "mod.tar.gz")
	if err := os.WriteFile(tmpFile, compressed, 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}

	// 3. Calc checksum of the *compressed* data
	checksum = crypto.SHA256SumRaw(compressed)
	return tmpFile, checksum
}

func TestUploadModuleFiles(t *testing.T) {
	origFetchFile := fetchFile
	defer func() { fetchFile = origFetchFile }()

	content := []byte("encrypted memfs companion payload")
	compressed, err := util.Compress(content)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}

	// Stub out the downloader: return the compressed blob for the requested name.
	fetched := 0
	fetchFile = func(config *def.Config, peer, file_to_download, path, checksum string) ([]byte, error) {
		fetched++
		return compressed, nil
	}

	memPath := "mem:///multifilemod/data.txt"
	inv := def.ResolvedInvocation{
		ModuleFiles: []def.ResolvedModuleFile{
			{Name: "multifilemod.data.txt.gz", MemPath: memPath, Checksum: "ignored-in-stub"},
		},
	}

	memPaths, err := uploadModuleFiles("", inv)
	if err != nil {
		t.Fatalf("uploadModuleFiles: %v", err)
	}
	if len(memPaths) != 1 || memPaths[0] != memPath {
		t.Fatalf("unexpected mem paths: %v", memPaths)
	}
	if fetched != 1 {
		t.Fatalf("expected 1 fetch, got %d", fetched)
	}

	// The companion must be readable from memfs, decompressed.
	got, err := util.ReadFileAgent(memPath)
	if err != nil {
		t.Fatalf("read memfs companion: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("memfs content mismatch: got %q want %q", got, content)
	}

	util.RemoveFileAgent(memPath)
}

func TestUploadModuleFilesEmptyInvocation(t *testing.T) {
	origFetchFile := fetchFile
	defer func() { fetchFile = origFetchFile }()

	fetched := 0
	fetchFile = func(config *def.Config, peer, file_to_download, path, checksum string) ([]byte, error) {
		fetched++
		return nil, nil
	}

	// No ModuleFiles in the invocation => nothing is fetched or cached.
	memPaths, err := uploadModuleFiles("", def.ResolvedInvocation{})
	if err != nil {
		t.Fatalf("uploadModuleFiles: %v", err)
	}
	if memPaths != nil {
		t.Fatalf("expected nil mem paths, got %v", memPaths)
	}
	if fetched != 0 {
		t.Fatalf("expected no fetch, got %d", fetched)
	}
}

func TestModuleHandlerMultiFileStarlark(t *testing.T) {
	origFetchFile := fetchFile
	defer func() { fetchFile = origFetchFile }()

	// Main entry-point script (files[0]).
	mainSrc := `
def main(*args):
    if len(module_files) != 1:
        return "Fail: expected 1 companion file, got %d" % len(module_files)
    data = read_file(module_files[0])
    if "companion" not in data:
        return "Fail: companion content not readable"
    return "OK"
`
	mainCompressed, err := util.Compress([]byte(mainSrc))
	if err != nil {
		t.Fatalf("compress main: %v", err)
	}
	mainFile := filepath.Join(t.TempDir(), "multi.star.gz")
	if err := os.WriteFile(mainFile, mainCompressed, 0o600); err != nil {
		t.Fatalf("write main: %v", err)
	}

	// Companion file (files[1]), hosted compressed exactly like the C2 does.
	companionName := "test_multi.data.txt.gz"
	companionContent := "companion data from memfs"
	companionCompressed, err := util.Compress([]byte(companionContent))
	if err != nil {
		t.Fatalf("compress companion: %v", err)
	}
	companionFile := filepath.Join(t.TempDir(), companionName)
	if err := os.WriteFile(companionFile, companionCompressed, 0o600); err != nil {
		t.Fatalf("write companion: %v", err)
	}

	// Downloader stub: serve the right file by name.
	fetchFile = func(config *def.Config, peer, file_to_download, path, checksum string) ([]byte, error) {
		switch file_to_download {
		case mainFile:
			return mainCompressed, nil
		case companionName:
			return companionCompressed, nil
		}
		t.Fatalf("unexpected download request: %s", file_to_download)
		return nil, nil
	}

	inv := def.ResolvedInvocation{
		ModuleFiles: []def.ResolvedModuleFile{
			{
				Name:     companionName,
				MemPath:  "mem:///test_multi/data.txt",
				Checksum: crypto.SHA256SumRaw(companionCompressed),
			},
		},
	}

	out := ModuleHandler("", mainFile, "starlark", "test_multi", crypto.SHA256SumRaw(mainCompressed), inv)
	if !strings.Contains(out, "OK") {
		t.Fatalf("expected OK, got: %q", out)
	}

	// The companion must have landed in memfs for the script to read it.
	got, err := util.ReadFileAgent("mem:///test_multi/data.txt")
	if err != nil {
		t.Fatalf("companion not cached in memfs: %v", err)
	}
	if string(got) != companionContent {
		t.Fatalf("memfs content mismatch: got %q want %q", got, companionContent)
	}
	util.RemoveFileAgent("mem:///test_multi/data.txt")
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
	os.MkdirAll(binDir, 0o755)
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

func TestDownloadAndVerifyModuleRetryLimit(t *testing.T) {
	originalFetchFile := fetchFile
	defer func() { fetchFile = originalFetchFile }()

	callsCount := 0
	fetchFile = func(config *def.Config, peer, file_to_download, path, checksum string) ([]byte, error) {
		callsCount++
		return []byte("corrupted-payload"), nil
	}

	tempFile := filepath.Join(t.TempDir(), "test-retry.bin")

	_, err := downloadAndVerifyModule(tempFile, "expected-checksum-xyz", "")
	if err == nil {
		t.Fatalf("expected error, but got nil")
	}

	if callsCount != 3 {
		t.Errorf("expected exactly 3 attempts, got %d", callsCount)
	}

	if !strings.Contains(err.Error(), "checksum verification failed after 3 attempts") {
		t.Errorf("unexpected error message: %v", err)
	}
}
