package ftp

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
)

// TestHandleFTPTransfer_PathValidation tests that path generation works correctly for various path types
func TestHandleFTPTransfer_PathValidation(t *testing.T) {
	// Setup test environment
	tmpDir := t.TempDir()
	live.FileGetDir = filepath.Join(tmpDir, "downloads")

	testCases := []struct {
		name         string
		remotePath   string
		expectedPath string // expected local path structure (relative to FileGetDir)
	}{
		{
			name:         "Absolute path - Linux home directory",
			remotePath:   "/home/kali/zsh/completion.zsh",
			expectedPath: "home/kali/zsh/completion.zsh",
		},
		{
			name:         "Absolute path - /etc/passwd",
			remotePath:   "/etc/passwd",
			expectedPath: "etc/passwd",
		},
		{
			name:         "Relative path",
			remotePath:   "relative/file.txt",
			expectedPath: "relative/file.txt",
		},
		{
			name:         "Path traversal attempt",
			remotePath:   "../../../../etc/passwd",
			expectedPath: "passwd", // Should be flattened to basename
		},
		{
			name:         "Deep nested path",
			remotePath:   "/var/log/app/2024/01/20/debug.log",
			expectedPath: "var/log/app/2024/01/20/debug.log",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate paths
			writeDir, targetFile, tempFile, lockFile := GenerateGetFilePaths(tc.remotePath)

			// Check that all paths are within FileGetDir
			if !strings.HasPrefix(writeDir, live.FileGetDir) {
				t.Errorf("writeDir %s is not within FileGetDir %s", writeDir, live.FileGetDir)
			}
			if !strings.HasPrefix(targetFile, live.FileGetDir) {
				t.Errorf("targetFile %s is not within FileGetDir %s", targetFile, live.FileGetDir)
			}
			if !strings.HasPrefix(tempFile, live.FileGetDir) {
				t.Errorf("tempFile %s is not within FileGetDir %s", tempFile, live.FileGetDir)
			}
			if !strings.HasPrefix(lockFile, live.FileGetDir) {
				t.Errorf("lockFile %s is not within FileGetDir %s", lockFile, live.FileGetDir)
			}

			// Check expected path structure
			expectedFullPath := filepath.Join(live.FileGetDir, tc.expectedPath)
			if targetFile != expectedFullPath {
				t.Errorf("targetFile path incorrect: got %s, want %s", targetFile, expectedFullPath)
			}

			// Verify no path traversal
			if strings.Contains(targetFile, "..") {
				t.Errorf("targetFile contains traversal: %s", targetFile)
			}

			t.Logf("✓ Remote: %s -> Local: %s", tc.remotePath, targetFile)
		})
	}
}

// TestHandleFTPTransfer_AbsolutePathRegression specifically tests the bug fix for absolute paths
func TestHandleFTPTransfer_AbsolutePathRegression(t *testing.T) {
	// This test ensures that absolute remote paths like "/home/kali/zsh/completion.zsh"
	// are correctly handled and don't trigger "invalid path" errors

	tmpDir := t.TempDir()
	live.FileGetDir = filepath.Join(tmpDir, "downloads")

	// The exact path from the bug report
	remotePath := "/home/kali/zsh/completion.zsh"
	testContent := []byte("# zsh completion script")
	_ = crypto.SHA256Sum(string(testContent))

	// Verify that GenerateGetFilePaths handles this correctly
	writeDir, targetFile, tempFile, lockFile := GenerateGetFilePaths(remotePath)

	// Check that paths are within FileGetDir
	if !strings.HasPrefix(writeDir, live.FileGetDir) {
		t.Errorf("writeDir %s is not within FileGetDir %s", writeDir, live.FileGetDir)
	}
	if !strings.HasPrefix(targetFile, live.FileGetDir) {
		t.Errorf("targetFile %s is not within FileGetDir %s", targetFile, live.FileGetDir)
	}
	if !strings.HasPrefix(tempFile, live.FileGetDir) {
		t.Errorf("tempFile %s is not within FileGetDir %s", tempFile, live.FileGetDir)
	}
	if !strings.HasPrefix(lockFile, live.FileGetDir) {
		t.Errorf("lockFile %s is not within FileGetDir %s", lockFile, live.FileGetDir)
	}

	// Verify the structure is preserved (without leading /)
	expectedPath := filepath.Join(live.FileGetDir, "home/kali/zsh/completion.zsh")
	if targetFile != expectedPath {
		t.Errorf("targetFile path incorrect: got %s, want %s", targetFile, expectedPath)
	}

	// Verify that the path doesn't contain ".." or other traversal attempts
	if strings.Contains(targetFile, "..") {
		t.Errorf("targetFile contains traversal: %s", targetFile)
	}

	t.Logf("✓ Absolute path correctly handled:")
	t.Logf("  Remote: %s", remotePath)
	t.Logf("  Local:  %s", targetFile)
	t.Logf("  Temp:   %s", tempFile)
	t.Logf("  Lock:   %s", lockFile)
}

// TestHandleFTPTransfer_TraversalPrevention tests that path traversal is prevented
func TestHandleFTPTransfer_TraversalPrevention(t *testing.T) {
	tmpDir := t.TempDir()
	live.FileGetDir = filepath.Join(tmpDir, "downloads")

	maliciousPaths := []string{
		"../../../../etc/passwd",
		"../../../etc/shadow",
		"../../.ssh/id_rsa",
		"./../../secrets.txt",
	}

	for _, malPath := range maliciousPaths {
		t.Run(malPath, func(t *testing.T) {
			writeDir, targetFile, _, _ := GenerateGetFilePaths(malPath)

			// Verify paths are contained within FileGetDir
			if !strings.HasPrefix(writeDir, live.FileGetDir) {
				t.Errorf("Path traversal detected in writeDir: %s escapes %s", writeDir, live.FileGetDir)
			}
			if !strings.HasPrefix(targetFile, live.FileGetDir) {
				t.Errorf("Path traversal detected in targetFile: %s escapes %s", targetFile, live.FileGetDir)
			}

			// Verify no ".." in final path
			if strings.Contains(targetFile, "..") {
				t.Errorf("Path still contains '..': %s", targetFile)
			}

			t.Logf("✓ Malicious path safely handled: %s -> %s", malPath, targetFile)
		})
	}
}
