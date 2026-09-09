package live

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// TestDownloadExtractConfigKeepsHistory is a regression test for the operator
// console command history: DownloadExtractConfig runs cleanupConfig on every
// operator start, and cleanup must NOT remove *.history files (the console
// persists its history to <workspace>/emp3r0r.history). Stale config/cert
// files (.json/.pem) must still be cleaned for a fresh start.
func TestDownloadExtractConfigKeepsHistory(t *testing.T) {
	// 1. Setup a throwaway environment (mirrors TestDownloadExtractConfig)
	tmpDir := t.TempDir()

	originalHome := os.Getenv("HOME")
	defer os.Setenv("HOME", originalHome)
	os.Setenv("HOME", tmpDir)

	originalUserProfile := os.Getenv("USERPROFILE")
	defer os.Setenv("USERPROFILE", originalUserProfile)
	os.Setenv("USERPROFILE", tmpDir)

	prefixDir := filepath.Join(tmpDir, "usr/local")
	originalPrefix := os.Getenv("EMP3R0R_PREFIX")
	defer os.Setenv("EMP3R0R_PREFIX", originalPrefix)
	os.Setenv("EMP3R0R_PREFIX", prefixDir)

	empDataDir := filepath.Join(prefixDir, "lib/emp3r0r")
	if err := os.MkdirAll(empDataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(empDataDir, "emp3r0r-cat"), []byte("dummy"), 0o755); err != nil {
		t.Fatal(err)
	}

	EmpWorkSpace = filepath.Join(tmpDir, ".emp3r0r")
	if err := os.MkdirAll(EmpWorkSpace, 0o700); err != nil {
		t.Fatal(err)
	}

	// 2. Seed the workspace with operator history and stale config/certs.
	histFile := filepath.Join(EmpWorkSpace, "emp3r0r.history")
	histContent := "{\"datetime\":\"2026-09-09T00:00:00Z\",\"block\":\"agents\"}\n"
	if err := os.WriteFile(histFile, []byte(histContent), 0o600); err != nil {
		t.Fatal(err)
	}
	otherHist := filepath.Join(EmpWorkSpace, "scratch.history")
	if err := os.WriteFile(otherHist, []byte("old session\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stalePem := filepath.Join(EmpWorkSpace, "operator.pem")
	if err := os.WriteFile(stalePem, []byte("old cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	staleJSON := filepath.Join(EmpWorkSpace, "emp3r0r.json")
	if err := os.WriteFile(staleJSON, []byte("old config"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 3. Tarball with the fresh operator config.
	tarSrcDir := filepath.Join(tmpDir, "tar_src")
	if err := os.MkdirAll(tarSrcDir, 0o700); err != nil {
		t.Fatal(err)
	}
	freshName := "fresh_config.txt"
	if err := os.WriteFile(filepath.Join(tarSrcDir, freshName), []byte("fresh"), 0o600); err != nil {
		t.Fatal(err)
	}
	tarPath := filepath.Join(tmpDir, "config.tar.gz")
	if err := util.TarArchive(filepath.Join(tarSrcDir, freshName), tarPath); err != nil {
		t.Fatalf("failed to create tar.gz: %v", err)
	}

	downloader := func(url, dest string) error {
		src, err := os.Open(tarPath)
		if err != nil {
			return err
		}
		defer src.Close()

		dst, err := os.Create(dest)
		if err != nil {
			return err
		}
		defer dst.Close()

		_, err = io.Copy(dst, src)
		return err
	}

	// 4. Fetch the fresh config (as the operator client does at startup).
	IsServer = false
	if err := DownloadExtractConfig("http://dummy/url", downloader); err != nil {
		t.Fatalf("DownloadExtractConfig failed: %v", err)
	}

	// 5. History must have survived; stale configs must be gone.
	if content, err := os.ReadFile(histFile); err != nil || string(content) != histContent {
		t.Fatalf("emp3r0r.history was not preserved: content=%q err=%v", content, err)
	}
	if _, err := os.Stat(otherHist); err != nil {
		t.Fatalf("scratch.history was removed by cleanup: %v", err)
	}
	if _, err := os.Stat(stalePem); err == nil {
		t.Fatal("stale .pem should have been cleaned")
	}
	if _, err := os.Stat(staleJSON); err == nil {
		t.Fatal("stale .json should have been cleaned")
	}
	if _, err := os.Stat(filepath.Join(EmpWorkSpace, freshName)); err != nil {
		t.Fatalf("fresh config not extracted: %v", err)
	}
}
