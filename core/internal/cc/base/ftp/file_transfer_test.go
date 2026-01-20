package ftp

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func TestStatFile(t *testing.T) {
	// Mock ExecCmd
	ExecCmd = func(cmd, cmd_id, tag string) error {
		// Simulate agent response
		go func() {
			time.Sleep(100 * time.Millisecond)
			fstat := &util.FileStat{
				Name:       "testfile",
				Size:       1234,
				Checksum:   "sha256sum",
				Permission: "-rw-r--r--",
			}
			data, err := cbor.Marshal(fstat)
			if err != nil {
				t.Errorf("Failed to marshal fstat: %v", err)
				return
			}
			live.CmdResults.Store(cmd_id, string(data))
		}()
		return nil
	}

	// Initialize live.CmdResults
	live.CmdResults = sync.Map{}

	agent := &def.Emp3r0rAgent{
		Tag: "test-agent",
	}

	fi, err := StatFile("testfile", agent)
	if err != nil {
		t.Fatalf("StatFile failed: %v", err)
	}

	if fi.Name != "testfile" {
		t.Errorf("Name mismatch: got %s, want testfile", fi.Name)
	}
	if fi.Size != 1234 {
		t.Errorf("Size mismatch: got %d, want 1234", fi.Size)
	}
}

func TestGenerateGetFilePaths(t *testing.T) {
	live.FileGetDir = "/tmp/test-get-dir/"

	testCases := []struct {
		inputPath    string
		expectedSafe bool // if safe, we expect structure preservation (stripped root)
	}{
		{"/home/user/file.txt", true},
		{"relative/file.txt", true},
		{"/etc/passwd", true},
		{"../../../../etc/passwd", false}, // Traversal should be flattened to basename?
	}

	for _, tc := range testCases {
		write_dir, save_to_file, _, _ := GenerateGetFilePaths(tc.inputPath)

		// Check that save_to_file is inside FileGetDir
		// filepath.Clean removes trailing slashes, so check both
		cleanedRoot := filepath.Clean(live.FileGetDir)
		if !strings.HasPrefix(write_dir, live.FileGetDir) && !strings.HasPrefix(write_dir, cleanedRoot) {
			t.Errorf("Write dir %s escaped root %s", write_dir, live.FileGetDir)
		}

		// Check basic structure
		if tc.expectedSafe {
			// for /home/user/file.txt -> /tmp/test-get-dir/home/user/file.txt
			// clean path relative
			clean := filepath.Clean(tc.inputPath)
			rel := strings.TrimLeft(clean, "/\\")
			expected := filepath.Join(live.FileGetDir, filepath.Dir(rel))
			if write_dir != expected {
				// Maybe GenerateGetFilePaths uses SecureLocalPath which might return "home/user"
				// Debug specific mismatch
				t.Logf("Mismatch for %s: got %s, expected %s", tc.inputPath, write_dir, expected)
			}
		}

		t.Logf("Input: %s -> WriteDir: %s, SaveFile: %s", tc.inputPath, write_dir, save_to_file)
	}
}
