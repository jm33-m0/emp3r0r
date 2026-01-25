package modules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
)

func TestDownloadAndVerifyModuleError(t *testing.T) {
	_, err := downloadAndVerifyModule("does-not-exist", "bad", "")
	if err == nil {
		t.Fatalf("expected error for missing file and download failure")
	}
	if !strings.Contains(err.Error(), "failed to initialize HTTP client") && !strings.Contains(err.Error(), "HTTP GET") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDownloadAndVerifyModuleSuccessLocal(t *testing.T) {
	data := []byte("hello-downloader")
	file := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	checksum := crypto.SHA256SumRaw(data)

	got, err := downloadAndVerifyModule(file, checksum, "")
	if err != nil {
		t.Fatalf("downloadAndVerifyModule: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("data mismatch: got %q want %q", string(got), string(data))
	}
}
