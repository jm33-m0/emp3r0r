package c2transport

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func TestFetchFile(t *testing.T) {
	// 1. Setup Mock C2 Server
	fileContent := []byte("hello p2p")
	checksum := crypto.SHA256SumRaw(fileContent)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify URL format matches DownloadViaC2 expectation
		// C2 logic: /DownloadFile2AgentAPI/AgentUUID?file_to_download=...
		// Note transport.DownloadFile2AgentAPI is a constant path segment

		// Simple check for parameter
		fileParam := r.URL.Query().Get("file_to_download")
		if fileParam == "test_file.txt" {
			w.Write(fileContent)
		} else {
			http.Error(w, "Not found", http.StatusNotFound)
		}
	}))
	defer ts.Close()

	// 2. Configure Agent
	oldCCAddress := def.CCAddress
	def.CCAddress = ts.URL
	def.HTTPClient = ts.Client()
	defer func() { def.CCAddress = oldCCAddress }()

	common.RuntimeConfig = &def.Config{
		AgentUUID: "test-agent-uuid",
	}

	// 3. Test DownloadViaC2 (to Memory)
	t.Run("DownloadViaC2_Memory", func(t *testing.T) {
		data, err := DownloadViaC2("test_file.txt", "", checksum)
		if err != nil {
			t.Fatalf("DownloadViaC2 failed: %v", err)
		}
		if string(data) != string(fileContent) {
			t.Errorf("Content mismatch: got %s, want %s", data, fileContent)
		}
	})

	// 4. Test DownloadViaC2 (to Disk)
	t.Run("DownloadViaC2_Disk", func(t *testing.T) {
		tmpFile := filepath.Join(os.TempDir(), "test_download.txt")
		defer os.Remove(tmpFile)

		_, err := DownloadViaC2("test_file.txt", tmpFile, checksum)
		if err != nil {
			t.Fatalf("DownloadViaC2 to disk failed: %v", err)
		}

		// Verify content
		// Note: helper encrypts it?
		// Wait, DownloadViaC2 implementation:
		// If path != "", it uses `grab`.
		// grab downloads to file.
		// THEN implementation logic:
		// defer func() { ... ReadFileAgent, WriteFileAgent ... }()
		// So it re-writes it encrypted.

		// We trust ReadFileAgent to decrypt
		readData, err := util.ReadFileAgent(tmpFile)
		if err != nil {
			t.Fatalf("ReadFileAgent failed: %v", err)
		}
		if string(readData) != string(fileContent) {
			t.Errorf("Content mismatch on disk: got %s, want %s", readData, fileContent)
		}
	})

	// 5. Test FetchFile (wraps DownloadViaC2 if no addr)
	t.Run("FetchFile_Local_Cache", func(t *testing.T) {
		// Mock local file existence
		localPath := filepath.Join(os.TempDir(), "local_cache.txt")
		util.WriteFileAgent(localPath, fileContent, 0600)
		defer util.RemoveFileAgent(localPath)

		// FetchFile should prefer local file if checksum matches
		data, err := FetchFile("", "remote_name_ignored.txt", localPath, checksum)
		if err != nil {
			t.Fatalf("FetchFile local cache failed: %v", err)
		}
		if string(data) != string(fileContent) {
			t.Errorf("Content mismatch: got %s", data)
		}
	})

	// Test FetchFile fallback to C2
	t.Run("FetchFile_Fallback_C2", func(t *testing.T) {
		// No address -> fallback to DownloadViaC2
		data, err := FetchFile("", "test_file.txt", "", checksum)
		if err != nil {
			t.Fatalf("FetchFile fallback failed: %v", err)
		}
		if string(data) != string(fileContent) {
			t.Errorf("Content mismatch: %s", data)
		}
	})
}
