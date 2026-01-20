package c2transport

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func TestHandleClient_PathTraversal(t *testing.T) {
	// Setup AgentRoot
	tmpDir, err := os.MkdirTemp("", "agent_root")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	common.RuntimeConfig = &def.Config{
		AgentRoot: tmpDir,
	}

	// Create a safe file in AgentRoot
	safeFile := filepath.Join(tmpDir, "safe.txt")
	err = util.WriteFileAgent(safeFile, []byte("safe content"), 0600)
	if err != nil {
		t.Fatalf("Failed to create safe file: %v", err)
	}

	// Create a file outside AgentRoot
	outsideDir, err := os.MkdirTemp("", "outside_root")
	if err != nil {
		t.Fatalf("Failed to create outside temp dir: %v", err)
	}
	defer os.RemoveAll(outsideDir)
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	err = os.WriteFile(outsideFile, []byte("secret content"), 0600)
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
				// if StatusOK but expectedBody is "", we check if it failed to read
				if tt.expectedBody == "" && rr.Code == http.StatusInternalServerError {
					// expected as it downloads from CC and fails (not implemented in test)
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
