package server

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
)

func TestCompleteWorkflow_MultiOperator(t *testing.T) {
	// Setup workspace and certs
	tempDir, err := os.MkdirTemp("", "emp3r0r-e2e-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	live.EmpWorkSpace = tempDir
	live.WWWRoot = filepath.Join(tempDir, "www")
	os.MkdirAll(live.WWWRoot, 0700)

	transport.CaCrtFile = filepath.Join(tempDir, "ca-cert.pem")
	transport.CaKeyFile = filepath.Join(tempDir, "ca-key.pem")
	transport.OperatorCaCrtFile = filepath.Join(tempDir, "operator-ca-cert.pem")
	transport.OperatorCaKeyFile = filepath.Join(tempDir, "operator-ca-key.pem")
	transport.OperatorServerCrtFile = filepath.Join(tempDir, "operator-server-cert.pem")
	transport.OperatorServerKeyFile = filepath.Join(tempDir, "operator-server-key.pem")

	// Generate certs
	_, err = transport.GenCerts(nil, transport.CaCrtFile, transport.CaKeyFile, "", "", true)
	if err != nil {
		t.Fatalf("GenCerts (CA): %v", err)
	}
	_, err = transport.GenCerts(nil, transport.OperatorCaCrtFile, transport.OperatorCaKeyFile, "", "", true)
	if err != nil {
		t.Fatalf("GenCerts (Op CA): %v", err)
	}

	// Important: We need a stable IP for the SANs that we will use in SNI
	netutil.WgOperatorIP = "10.0.0.1"

	// Generate operator server cert with multiple operator IPs in SANs
	_, err = transport.GenCerts([]string{"10.0.0.1", "10.0.0.2"}, transport.OperatorServerCrtFile, transport.OperatorServerKeyFile, transport.OperatorCaKeyFile, transport.OperatorCaCrtFile, false)
	if err != nil {
		t.Fatalf("GenCerts (Op Server): %v", err)
	}

	cert, err := tls.LoadX509KeyPair(transport.OperatorServerCrtFile, transport.OperatorServerKeyFile)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}

	// Prepare files for each operator
	os.WriteFile(filepath.Join(live.WWWRoot, "file1.txt"), []byte("Hello from Operator 1"), 0600)
	os.WriteFile(filepath.Join(live.WWWRoot, "file2.txt"), []byte("Hello from Operator 2"), 0600)

	// Setup Mock Relay Server for Operator 1
	r1 := mux.NewRouter()
	r1.HandleFunc("/api/www/{token}", func(w http.ResponseWriter, r *http.Request) {
		fileName := r.URL.Query().Get("file_to_download")
		http.ServeFile(w, r, filepath.Join(live.WWWRoot, fileName))
	})
	s1 := httptest.NewUnstartedServer(r1)
	s1.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s1.StartTLS()
	defer s1.Close()

	// Setup Mock Relay Server for Operator 2
	r2 := mux.NewRouter()
	r2.HandleFunc("/api/www/{token}", func(w http.ResponseWriter, r *http.Request) {
		fileName := r.URL.Query().Get("file_to_download")
		http.ServeFile(w, r, filepath.Join(live.WWWRoot, fileName))
	})
	s2 := httptest.NewUnstartedServer(r2)
	s2.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s2.StartTLS()
	defer s2.Close()

	// CC Server Dispatcher Setup
	live.RuntimeConfig.CheckInPath = "checkin"
	live.RuntimeConfig.MsgPath = "msg"

	tests := []struct {
		name     string
		relay    *httptest.Server
		fileName string
		expected string
	}{
		{
			name:     "Operator 1",
			relay:    s1,
			fileName: "file1.txt",
			expected: "Hello from Operator 1",
		},
		{
			name:     "Operator 2",
			relay:    s2,
			fileName: "file2.txt",
			expected: "Hello from Operator 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			relayAddr := tt.relay.Listener.Addr().(*net.TCPAddr)
			netutil.WgRelayedHTTPPort = relayAddr.Port
			relayIP := relayAddr.IP.String()

			req := httptest.NewRequest("GET", "/api/www/token123?file_to_download="+tt.fileName, nil)
			req.RemoteAddr = net.JoinHostPort(relayIP, "54321")
			req = mux.SetURLVars(req, map[string]string{
				"prefix": "api",
				"api":    "www",
				"token":  "token123",
			})

			w := httptest.NewRecorder()
			apiDispatcher(w, req)

			resp := w.Result()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected OK, got %v: %s", resp.Status, string(body))
			}
			if string(body) != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, string(body))
			}
		})
	}
}
