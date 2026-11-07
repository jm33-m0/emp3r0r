package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkspaceWriteReadEdit(t *testing.T) {
	root := t.TempDir()
	ws, err := NewWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ws.Write("modules/demo/stub.c", "int main(void) { return 1; }\n"); err != nil {
		t.Fatal(err)
	}
	got, err := ws.Read("modules/demo/stub.c", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.(map[string]any)["content"].(string), "return 1") {
		t.Fatalf("read = %#v", got)
	}
	if _, err := ws.Edit("modules/demo/stub.c", "return 1", "return 0", false); err != nil {
		t.Fatal(err)
	}
	got, err = ws.Read("modules/demo/stub.c", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.(map[string]any)["content"].(string), "return 0") {
		t.Fatalf("edit = %#v", got)
	}
	if _, err := ws.Write("dup.txt", "foo foo"); err != nil {
		t.Fatal(err)
	}
	if _, err := ws.Edit("dup.txt", "foo", "bar", false); err == nil {
		t.Fatal("non-unique edit should fail")
	}
	if _, err := ws.Edit("dup.txt", "foo", "bar", true); err != nil {
		t.Fatalf("replace all: %v", err)
	}
}

func TestWorkspaceRejectsEscapes(t *testing.T) {
	root := t.TempDir()
	ws, err := NewWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../outside", "/etc/passwd", "a/../../b", "assistant.json", "sub/mcp_audit.log", ".git/config", "operator.key", "wg_config.json", "emp3r0r.json", "magic_string", "emp3r0r.history", ".omp/mcp.json", ".module-toolchain/zig", "stub-linux-amd64"} {
		if _, err := ws.Write(path, "x"); err == nil {
			t.Errorf("write %q should fail", path)
		}
	}

	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := ws.Write("link/escape", "x"); err == nil {
		t.Fatal("write through symlink should fail")
	}

	hard := filepath.Join(outside, "hard")
	if err := os.WriteFile(hard, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(hard, filepath.Join(root, "hardlink")); err != nil {
		t.Skipf("hardlink unavailable: %v", err)
	}
	if _, err := ws.Write("hardlink", "x"); err == nil {
		t.Fatal("write through hardlink should fail")
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
