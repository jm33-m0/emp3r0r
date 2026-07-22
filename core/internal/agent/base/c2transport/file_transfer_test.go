package c2transport

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func TestHandleClient_PathTraversal(t *testing.T) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), "agent_root")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	common.RuntimeConfig = &def.Config{}

	safeFile := filepath.Join(os.TempDir(), "safe.txt")
	err = util.WriteFileAgent(safeFile, []byte("safe content"), 0o600)
	if err != nil {
		t.Fatalf("Failed to create safe file: %v", err)
	}

	outsideDir, err := os.MkdirTemp("", "outside_root")
	if err != nil {
		t.Fatalf("Failed to create outside temp dir: %v", err)
	}
	defer os.RemoveAll(outsideDir)
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	err = os.WriteFile(outsideFile, []byte("secret content"), 0o600)
	if err != nil {
		t.Fatalf("Failed to create outside file: %v", err)
	}

	tests := []struct {
		name           string
		filePath       string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Safe file request",
			filePath:       "safe.txt",
			expectedStatus: http.StatusOK,
			expectedBody:   "safe content",
		},
		{
			name:           "Path traversal attempt (../)",
			filePath:       "../secret.txt",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid file path\n",
		},
		{
			name:           "Absolute path attempt",
			filePath:       outsideFile,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid file path\n",
		},
		{
			name:           "Invalid file path (empty)",
			filePath:       "",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid file path\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", fmt.Sprintf("/?file_path=%s", tt.filePath), nil)
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(handleClient)

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				if tt.expectedBody == "" && rr.Code == http.StatusInternalServerError {
					return
				}
				t.Errorf("handler returned wrong status code: got %v want %v",
					rr.Code, tt.expectedStatus)
			}

			if tt.expectedBody != "" && rr.Body.String() != tt.expectedBody {
				t.Errorf("handler returned unexpected body: got %v want %v",
					rr.Body.String(), tt.expectedBody)
			}
		})
	}
}

func TestFileTransfer_EndToEnd(t *testing.T) {
	// Initialize real runtime configuration
	common.RuntimeConfig = &def.Config{
		Password:          "e2e_test_password_123",
		P2PTransport:      "mtls",
		CamouflageCertOrg: "emp3r0r test org",
		CamouflageCertCN:  "emp3r0r test cn",
	}

	// Set file crypto key
	testKey := []byte("12345678901234567890123456789012")
	util.SetFileCryptoKey(testKey)

	// Create test file in TempDir (which is served safely by FileServer/handleClient)
	fileName := fmt.Sprintf("e2e_transfer_%d.txt", time.Now().UnixNano())
	safeFilePath := filepath.Join(os.TempDir(), fileName)
	testContent := []byte("Real end-to-end P2P file transfer test content! 123456789")

	if err := util.WriteFileAgent(safeFilePath, testContent, 0o600); err != nil {
		t.Fatalf("Failed to write test source file: %v", err)
	}
	defer os.Remove(safeFilePath)

	checksum := crypto.SHA256SumRaw(testContent)

	// Start real FileServer on a random port
	port := util.RandInt(30000, 45000)
	portStr := fmt.Sprintf("%d", port)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := FileServer(port, ctx, cancel); err != nil {
			t.Logf("FileServer exited: %v", err)
		}
	}()

	// Wait until FileServer P2P port is open
	serverReady := false
	for range 30 {
		if netutil.IsPortOpen("127.0.0.1", portStr) {
			serverReady = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !serverReady {
		t.Fatalf("FileServer failed to open P2P port %s", portStr)
	}

	t.Run("Disk Transfer End-to-End", func(t *testing.T) {
		destDir, err := os.MkdirTemp("", "dl_disk_test")
		if err != nil {
			t.Fatalf("Failed to create temp dest dir: %v", err)
		}
		defer os.RemoveAll(destDir)

		destPath := filepath.Join(destDir, "downloaded.txt")

		// Perform real P2P download
		err = FetchFileKCP("127.0.0.1:"+portStr, fileName, destPath, checksum)
		if err != nil {
			t.Fatalf("FetchFileKCP failed for disk download: %v", err)
		}

		// Read and verify downloaded file
		downloadedData, err := util.ReadFileAgent(destPath)
		if err != nil {
			t.Fatalf("Failed to read downloaded disk file: %v", err)
		}

		if string(downloadedData) != string(testContent) {
			t.Fatalf("Downloaded content mismatch: got %q, want %q", string(downloadedData), string(testContent))
		}
	})

	t.Run("MemFS Virtual Memory Transfer End-to-End", func(t *testing.T) {
		destMemPath := fmt.Sprintf("mem:///downloaded_%d.txt", time.Now().UnixNano())

		// Perform real P2P download to mem:/// path
		err := FetchFileKCP("127.0.0.1:"+portStr, fileName, destMemPath, checksum)
		if err != nil {
			t.Fatalf("FetchFileKCP failed for mem:/// download: %v", err)
		}

		// Read back from mem:/// using ReadFileAgent
		downloadedData, err := util.ReadFileAgent(destMemPath)
		if err != nil {
			t.Fatalf("Failed to read downloaded mem:/// file: %v", err)
		}

		if string(downloadedData) != string(testContent) {
			t.Fatalf("Downloaded mem:/// content mismatch: got %q, want %q", string(downloadedData), string(testContent))
		}
	})

	t.Run("Serving From MemFS End-to-End", func(t *testing.T) {
		memFileName := fmt.Sprintf("mem:///hosted_%d.txt", time.Now().UnixNano())
		memContent := []byte("Content stored inside host agent memfs virtual filesystem!")

		// Save file in host agent memfs
		if err := util.WriteFileAgent(memFileName, memContent, 0o600); err != nil {
			t.Fatalf("Failed to write to memfs: %v", err)
		}

		memChecksum := crypto.SHA256SumRaw(memContent)
		destMemPath := fmt.Sprintf("mem:///received_from_memfs_%d.txt", time.Now().UnixNano())

		// Fetch file hosted in memfs over P2P
		err := FetchFileKCP("127.0.0.1:"+portStr, memFileName, destMemPath, memChecksum)
		if err != nil {
			t.Fatalf("FetchFileKCP failed for memfs source file: %v", err)
		}

		// Read back from requester memfs
		receivedData, err := util.ReadFileAgent(destMemPath)
		if err != nil {
			t.Fatalf("Failed to read received memfs file: %v", err)
		}

		if string(receivedData) != string(memContent) {
			t.Fatalf("MemFS transfer mismatch: got %q, want %q", string(receivedData), string(memContent))
		}
	})
}
