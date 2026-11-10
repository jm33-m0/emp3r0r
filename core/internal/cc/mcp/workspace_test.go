package mcp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateUploadSourceRejectsProtectedAndSymlinkPaths(t *testing.T) {
	for _, path := range []string{
		"assistant.json",
		"sub/mcp_audit.log",
		".git/config",
		"operator.key",
		"wg_config.json",
		"emp3r0r.json",
		"magic_string",
		"emp3r0r.history",
		".omp/mcp.json",
		".ssh/id_ed25519",
		".aws/credentials",
		".kube/config",
		".module-toolchain/zig",
		"stub-linux-amd64",
		"/proc/self/cmdline",
		"/proc/self/environ",
		"/sys/kernel/notes",
		"/dev/fd/0",
		"/run/secrets/operator",
		"/proc/self/../self/cmdline",
	} {
		if err := validateUploadSource(path); err == nil {
			t.Errorf("validateUploadSource(%q) should fail", path)
		}
	}

	dir := t.TempDir()
	secret := filepath.Join(dir, "wg_config.json")
	if err := os.WriteFile(secret, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "harmless.bin")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := validateUploadSource(link); err == nil {
		t.Fatal("symlink to protected file should be rejected")
	}

	danglingDir := filepath.Join(dir, "dangling-dir")
	if err := os.Symlink(filepath.Join(dir, "missing-dir"), danglingDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := validateUploadSource(filepath.Join(danglingDir, "payload.bin")); err == nil {
		t.Fatal("dangling symlink ancestor should be rejected")
	}
}

func TestValidateLocalBuildPathRejectsProtectedPaths(t *testing.T) {
	dir := t.TempDir()
	for _, path := range []string{
		filepath.Join(dir, "mcp.json"),
		filepath.Join(dir, "mcp_audit.log"),
		filepath.Join(dir, "emp3r0r.json"),
		filepath.Join(dir, "wg_config.json"),
		"/proc/self/cmdline",
		"/sys/kernel/notes",
	} {
		if err := validateLocalBuildPath("output", path); err == nil {
			t.Errorf("validateLocalBuildPath(%q) should fail", path)
		}
	}

	subdir := filepath.Join(dir, "outdir")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateLocalBuildPath("output", subdir); err == nil {
		t.Fatal("directory output should be rejected")
	}
	if err := validateLocalBuildPath("payload-path", "/"); err != nil {
		t.Fatalf("remote payload path rejected: %v", err)
	}

	secret := filepath.Join(dir, "wg_config.json")
	if err := os.WriteFile(secret, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "output.bin")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := validateLocalBuildPath("output", link); err == nil {
		t.Fatal("symlink to a protected path should be rejected")
	}

	dangling := filepath.Join(dir, "dangling-output.bin")
	if err := os.Symlink(filepath.Join(dir, "missing-target"), dangling); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := validateLocalBuildPath("output", dangling); err == nil {
		t.Fatal("dangling symlink output should be rejected")
	}
	danglingDir := filepath.Join(dir, "dangling-dir")
	if err := os.Symlink(filepath.Join(dir, "missing-dir"), danglingDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := validateLocalBuildPath("output", filepath.Join(danglingDir, "output.bin")); err == nil {
		t.Fatal("dangling symlink ancestor should be rejected")
	}

	safe := filepath.Join(t.TempDir(), "output.bin")
	if err := validateLocalBuildPath("output", safe); err != nil {
		t.Fatalf("safe output path rejected: %v", err)
	}
}

func TestLimiterBoundsBurst(t *testing.T) {
	l := NewLimiter(60, 1)
	if ok, _ := l.Allow(); !ok {
		t.Fatal("first token should pass")
	}
	if ok, wait := l.Allow(); ok || wait <= 0 {
		t.Fatalf("second token = %v, wait = %v", ok, wait)
	}
}
