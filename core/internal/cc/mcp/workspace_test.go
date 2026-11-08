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
