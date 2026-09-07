package tools

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// TestUnlockDownloadsRemovesStaleLocks verifies that incomplete-download lock
// files are removed by UnlockDownloads, leaving real files untouched.
func TestUnlockDownloadsRemovesStaleLocks(t *testing.T) {
	dir := t.TempDir()
	orig := live.FileGetDir
	live.FileGetDir = dir + string(os.PathSeparator)
	defer func() { live.FileGetDir = orig }()

	names := []string{"file.bin.lock", "other.bin.lock"}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	realFile := "keep.txt"
	if err := os.WriteFile(filepath.Join(dir, realFile), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := UnlockDownloads(); err != nil {
		t.Fatalf("UnlockDownloads: %v", err)
	}
	for _, n := range names {
		if _, err := os.Stat(filepath.Join(dir, n)); !os.IsNotExist(err) {
			t.Errorf("stale lock %s was not removed", n)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, realFile)); err != nil {
		t.Errorf("non-lock file was removed: %v", err)
	}
}
