package live

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/arc/v2"
)

func TestDownloadExtractConfig(t *testing.T) {
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

	// Create necessary directories and files for SetupFilePaths
	empDataDir := filepath.Join(prefixDir, "lib/emp3r0r")
	if err := os.MkdirAll(empDataDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Create dummy emp3r0r-cat
	if err := os.WriteFile(filepath.Join(empDataDir, "emp3r0r-cat"), []byte("dummy"), 0755); err != nil {
		t.Fatal(err)
	}

	// Set EmpWorkSpace to a valid directory for cleanupConfig
	EmpWorkSpace = filepath.Join(tmpDir, ".emp3r0r")
	if err := os.MkdirAll(EmpWorkSpace, 0700); err != nil {
		t.Fatal(err)
	}

	// 2. Create a dummy tarball using system tar command (to support xz)
	tarSrcDir := filepath.Join(tmpDir, "tar_src")
	if err := os.MkdirAll(tarSrcDir, 0700); err != nil {
		t.Fatal(err)
	}

	testFileName := "test_config_file.txt"
	testFileContent := "hello world"
	if err := os.WriteFile(filepath.Join(tarSrcDir, testFileName), []byte(testFileContent), 0600); err != nil {
		t.Fatal(err)
	}

	tarPath := filepath.Join(tmpDir, "config.tar.xz")
	// Create .tar.xz using arc library (cross-platform)
	if err := arc.Archive(filepath.Join(tarSrcDir, testFileName), tarPath, arc.CompressionMap["xz"], arc.ArchivalMap["tar"]); err != nil {
		t.Fatalf("Failed to create tar.xz: %v", err)
	}

	// 3. Mock downloader
	downloader := func(url, dest string) error {
		// Copy our dummy tarball to dest
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

	// 4. Run DownloadExtractConfig
	// Note: DownloadExtractConfig uses EmpConfigTar global, which is set in SetupFilePaths
	// But SetupFilePaths is called inside DownloadExtractConfig.
	// However, DownloadExtractConfig uses EmpConfigTar BEFORE calling SetupFilePaths if IsServer is true.
	// If IsServer is false (default), it uses a different path.

	// Let's ensure IsServer is false
	IsServer = false

	err := DownloadExtractConfig("http://dummy/url", downloader)
	if err != nil {
		t.Fatalf("DownloadExtractConfig failed: %v", err)
	}

	// 5. Verify extraction
	// The file should be extracted to HOME (tmpDir)
	extractedFile := filepath.Join(tmpDir, testFileName)
	content, err := os.ReadFile(extractedFile)
	if err != nil {
		t.Errorf("Failed to read extracted file: %v", err)
	}
	if string(content) != testFileContent {
		t.Errorf("Extracted content mismatch. Got %s, want %s", content, testFileContent)
	}
}
