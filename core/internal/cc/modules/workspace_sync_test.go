package modules

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestSyncModuleSourcesKeepsOperatorEdits(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(src, "src.c"), "old source")
	writeFile(t, filepath.Join(src, "edited.c"), "old install")
	writeFile(t, filepath.Join(dst, "src.c"), "old source")
	writeFile(t, filepath.Join(dst, "edited.c"), "old install")
	writeFile(t, filepath.Join(dst, "build.so"), "output")
	if err := recordSourceManifest(src, dst); err != nil {
		t.Fatalf("recordSourceManifest: %v", err)
	}

	writeFile(t, filepath.Join(src, "src.c"), "new source")
	writeFile(t, filepath.Join(src, "added.c"), "added")
	writeFile(t, filepath.Join(dst, "edited.c"), "operator edit")

	if err := syncModuleSources(src, dst); err != nil {
		t.Fatalf("syncModuleSources: %v", err)
	}

	for _, tc := range []struct{ file, want string }{
		{"src.c", "new source"},
		{"added.c", "added"},
		{"edited.c", "operator edit"},
		{"build.so", "output"},
	} {
		got, err := os.ReadFile(filepath.Join(dst, tc.file))
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		if string(got) != tc.want {
			t.Fatalf("%s = %q, want %q", tc.file, got, tc.want)
		}
	}
}

func TestSyncModuleSourcesMigratesWorkspaceWithoutManifest(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(src, "src.c"), "current install")
	writeFile(t, filepath.Join(dst, "src.c"), "stale copy")

	if err := syncModuleSources(src, dst); err != nil {
		t.Fatalf("syncModuleSources: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "src.c"))
	if err != nil {
		t.Fatalf("read src.c: %v", err)
	}
	if string(got) != "current install" {
		t.Fatalf("src.c = %q, want the current install", got)
	}
	if _, ok := readSourceManifest(dst); !ok {
		t.Fatal("migration did not create a source manifest")
	}
}
