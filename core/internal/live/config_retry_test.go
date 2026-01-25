package live

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jm33-m0/arc/v2"
)

func TestDownloadExtractConfig_Retry(t *testing.T) {
	// 1. Setup environment
	tmpDir := t.TempDir()

	// Mock HOME
	originalHome := os.Getenv("HOME")
	defer os.Setenv("HOME", originalHome)
	os.Setenv("HOME", tmpDir)

	// Mock USERPROFILE for Windows
	originalUserProfile := os.Getenv("USERPROFILE")
	defer os.Setenv("USERPROFILE", originalUserProfile)
	os.Setenv("USERPROFILE", tmpDir)

	// Mock EMP3R0R_PREFIX
	prefixDir := filepath.Join(tmpDir, "usr/local")
	originalPrefix := os.Getenv("EMP3R0R_PREFIX")
	defer os.Setenv("EMP3R0R_PREFIX", originalPrefix)
	os.Setenv("EMP3R0R_PREFIX", prefixDir)

	// Create necessary directories and files
	empDataDir := filepath.Join(prefixDir, "lib/emp3r0r")
	os.MkdirAll(empDataDir, 0755)
	os.WriteFile(filepath.Join(empDataDir, "emp3r0r-cat"), []byte("dummy"), 0755)

	EmpWorkSpace = filepath.Join(tmpDir, ".emp3r0r")
	os.MkdirAll(EmpWorkSpace, 0700)

	// 2. Create a dummy tarball
	tarSrcDir := filepath.Join(tmpDir, "tar_src")
	os.MkdirAll(tarSrcDir, 0700)
	testFileName := "test_retry.txt"
	testFileContent := "retry success"
	os.WriteFile(filepath.Join(tarSrcDir, testFileName), []byte(testFileContent), 0600)
	tarPath := filepath.Join(tmpDir, "config.tar.xz")
	arc.Archive(filepath.Join(tarSrcDir, testFileName), tarPath, arc.CompressionMap["xz"], arc.ArchivalMap["tar"])

	// 3. Mock downloader with failures
	attempts := 0
	downloader := func(url, dest string) error {
		attempts++
		if attempts < 3 {
			return fmt.Errorf("simulated network failure %d", attempts)
		}
		// Copy our dummy tarball to dest on 3rd attempt
		src, _ := os.Open(tarPath)
		defer src.Close()
		dst, _ := os.Create(dest)
		defer dst.Close()
		io.Copy(dst, src)
		return nil
	}

	// 4. Run DownloadExtractConfig
	IsServer = false
	start := time.Now()
	err := DownloadExtractConfig("http://dummy/url", downloader)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("DownloadExtractConfig failed: %v", err)
	}

	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}

	// Should take at least 2 seconds due to retries
	if duration < 2*time.Second {
		t.Errorf("Expected duration >= 2s, got %v", duration)
	}

	// 5. Verify extraction
	extractedFile := filepath.Join(tmpDir, testFileName)
	content, _ := os.ReadFile(extractedFile)
	if string(content) != testFileContent {
		t.Errorf("Extracted content mismatch. Got %s, want %s", content, testFileContent)
	}
}
