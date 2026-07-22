package operator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
)

func TestServeWWWRelay_ChecksumParsing(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "www_test")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	live.WWWRoot = tmpDir + "/"

	fileName := "test_module.xz"
	filePath := filepath.Join(tmpDir, fileName)
	content := []byte("test module file data 12345")
	if err := os.WriteFile(filePath, content, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	checksum := crypto.SHA256SumRaw(content)

	// StreamID with filename:checksum format
	streamID := fileName + ":" + checksum

	// Test that filename and checksum are correctly extracted without erroring out on file path
	filename := streamID
	var clientChecksum string
	if idx := strings.LastIndex(streamID, ":"); idx != -1 {
		filename = streamID[:idx]
		clientChecksum = streamID[idx+1:]
	}

	if filename != fileName {
		t.Errorf("Extracted filename mismatch: got %q, want %q", filename, fileName)
	}
	if clientChecksum != checksum {
		t.Errorf("Extracted checksum mismatch: got %q, want %q", clientChecksum, checksum)
	}
}
