package modules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func TestModuleHandlerCOFFMustBeInMem(t *testing.T) {
	out := ModuleHandler("", "", "coff", "dummy", "", def.ResolvedInvocation{}, false)
	if out == "" || !strings.Contains(out, "in memory") {
		t.Fatalf("expected in-memory requirement error, got %q", out)
	}
}

func TestProcessModuleFilesSetsExecPerms(t *testing.T) {
	modDir, err := os.MkdirTemp("", "mod-files-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(modDir)

	filePath := filepath.Join(modDir, "run.sh")
	if writeErr := os.WriteFile(filePath, []byte("echo hi"), 0o600); writeErr != nil {
		t.Fatalf("write file: %v", writeErr)
	}

	if err := processModuleFiles(modDir); err != nil {
		t.Fatalf("processModuleFiles: %v", err)
	}

	info, statErr := os.Stat(filePath)
	if statErr != nil {
		t.Fatalf("stat file: %v", statErr)
	}

	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("permission not set to 0700: got %v", perm)
	}
}

func TestExtractModule(t *testing.T) {
	root := t.TempDir()
	modDir := filepath.Join(root, "mod")
	if err := os.MkdirAll(modDir, 0o700); err != nil {
		t.Fatalf("mkdir moddir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(modDir, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("write src file: %v", err)
	}

	tarball := filepath.Join(t.TempDir(), "src.tar.xz")
	if err := util.TarXZ(modDir, tarball); err != nil {
		t.Fatalf("TarXZ: %v", err)
	}

	common.RuntimeConfig.AgentRoot = root
	if err := extractModule(modDir, tarball); err != nil {
		t.Fatalf("extractModule: %v", err)
	}

	if !util.IsFileExist(filepath.Join(modDir, "a.txt")) {
		t.Fatalf("expected extracted file present")
	}
}

func TestPrepareModuleOnDisk(t *testing.T) {
	root := t.TempDir()
	modDir := filepath.Join(root, "mod")
	srcDir := modDir
	if err := os.MkdirAll(srcDir, 0o700); err != nil {
		t.Fatalf("mkdir srcDir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "b.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatalf("write src file: %v", err)
	}
	tarPath := filepath.Join(t.TempDir(), "mod.tar.xz")
	if err := util.TarXZ(srcDir, tarPath); err != nil {
		t.Fatalf("TarXZ: %v", err)
	}
	data, err := os.ReadFile(tarPath)
	if err != nil {
		t.Fatalf("read tar: %v", err)
	}

	common.RuntimeConfig.AgentRoot = root

	if err := prepareModuleOnDisk(tarPath, modDir, data); err != nil {
		t.Fatalf("prepareModuleOnDisk: %v", err)
	}

	filePath := filepath.Join(modDir, "b.txt")
	info, statErr := os.Stat(filePath)
	if statErr != nil {
		t.Fatalf("stat extracted: %v", statErr)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("permission not set to 0700: got %v", perm)
	}
}

func TestDownloadAndVerifyModuleError(t *testing.T) {
	_, err := downloadAndVerifyModule("does-not-exist", "bad", "")
	if err == nil {
		t.Fatalf("expected error for missing file and download failure")
	}
	if !strings.Contains(err.Error(), "failed to initialize HTTP client") && !strings.Contains(err.Error(), "HTTP GET") {
		t.Fatalf("unexpected error: %v", err)
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

func TestModuleHandlerSuccessOnDisk(t *testing.T) {
	root := t.TempDir()
	common.RuntimeConfig.AgentRoot = root

	modName := "dummy"
	// build a dummy module directory with an executable script; directory name must match module name
	modSrc := filepath.Join(t.TempDir(), modName)
	if err := os.MkdirAll(modSrc, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	script := "#!/bin/sh\necho hello-module\n"
	scriptPath := filepath.Join(modSrc, "run.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write script: %v", err)
	}

	tarPath := filepath.Join(t.TempDir(), "mod.tar.xz")
	if err := util.TarXZ(modSrc, tarPath); err != nil {
		t.Fatalf("TarXZ: %v", err)
	}
	checksum := crypto.SHA256SumFile(tarPath)

	// run ModuleHandler with on-disk execution
	inv := def.ResolvedInvocation{Argv: []string{"./run.sh"}}
	out := ModuleHandler("", tarPath, "other", modName, checksum, inv, false)
	if !strings.Contains(out, "hello-module") {
		t.Fatalf("expected module output, got %q", out)
	}
}
