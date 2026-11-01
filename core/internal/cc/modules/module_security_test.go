package modules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSafeComponentRejectsTraversal(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "../x", "a/b", `a\b`, "a\x00b", "-x"} {
		if got, err := safeComponent(bad); err == nil {
			t.Errorf("safeComponent(%q) = %q, want error", bad, got)
		}
	}
	for _, good := range []string{"sa_linux_env", "coffloader_linux.amd64.gz", ".hidden"} {
		if got, err := safeComponent(good); err != nil || got != good {
			t.Errorf("safeComponent(%q) = %q, %v; want it unchanged", good, got, err)
		}
	}
}

func TestModuleFilePathRejectsEscape(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"", "../x", "a/../../x", "/etc/passwd"} {
		if path, err := moduleFilePath(dir, bad); err == nil {
			t.Errorf("moduleFilePath(%q) = %q, want error", bad, path)
		}
	}
	got, err := moduleFilePath(dir, "SA/src/env.o")
	if err != nil {
		t.Fatalf("moduleFilePath valid payload: %v", err)
	}
	want := filepath.Join(dir, "SA/src/env.o")
	if got != want {
		t.Fatalf("moduleFilePath = %q, want %q", got, want)
	}
	if err := os.MkdirAll(filepath.Dir(got), 0o700); err != nil {
		t.Fatal(err)
	}
}
