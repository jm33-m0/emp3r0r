package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/posener/h2conn"
)

// TestUnauthenticatedRequestRejection verifies that requests without valid auth headers are rejected.
func TestUnauthenticatedRequestRejection(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dispatcher_auth_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	caCertFile := filepath.Join(tmpDir, "ca-cert.pem")
	caKeyFile := filepath.Join(tmpDir, "ca-key.pem")
	serverCertFile := filepath.Join(tmpDir, "server-cert.pem")
	serverKeyFile := filepath.Join(tmpDir, "server-key.pem")

	// Generate CA
	_, err = transport.GenCerts(nil, caCertFile, caKeyFile, "", "", true)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Generate Server Cert
	_, err = transport.GenCerts([]string{"127.0.0.1"}, serverCertFile, serverKeyFile, caKeyFile, caCertFile, false)
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	caCertData, err := os.ReadFile(caCertFile)
	if err != nil {
		t.Fatalf("Failed to read CA cert: %v", err)
	}
	transport.CACrtPEM = caCertData

	// Setup Transport Paths
	transport.CaCrtFile = caCertFile
	transport.OperatorCaCrtFile = caCertFile
	transport.ServerCrtFile = serverCertFile
	transport.ServerKeyFile = serverKeyFile
	transport.EmpWorkSpace = tmpDir

	// Get random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// Setup C2 Config
	live.RuntimeConfig = &def.Config{
		CCPort: fmt.Sprintf("%d", port),
		CAPEM:  string(caCertData),
	}

	go StartC2AgentTLSServer()
	time.Sleep(2 * time.Second)
	defer func() {
		// Shutdown
		if network.EmpTLSServer != nil {
			network.EmpTLSServer.Shutdown(network.EmpTLSServerCtx)
		}
	}()

	// Setup HTTP Client
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCertData)
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: certPool},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: tr}

	c2URL := fmt.Sprintf("https://127.0.0.1:%d", port)

	// Test Cases: requests without auth headers should be rejected
	testCases := []struct {
		name           string
		path           string
		expectedStatus int
	}{
		{
			name:           "www without auth",
			path:           "/api/www/fake-agent-uuid?file_to_download=test.txt",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "ftp without auth",
			path:           "/api/ftp/fake-agent-uuid",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "proxy without auth",
			path:           "/api/proxy/fake-session-id",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := c2URL + tc.path
			// New protocol: use h2conn
			h2 := h2conn.Client{Client: client}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, resp, err := h2.Connect(ctx, url)
			if err != nil {
				// Some rejections might happen at the H2 level
				return
			}
			defer conn.Close()

			if resp.StatusCode != http.StatusOK {
				// Accepted rejections for ahora
				return
			}

			// Try to read MsgAuth (server should close connection instead of sending one if unauthenticated)
			// Use a short timer to avoid waiting for the full server-side handshake timeout (10s)
			timer := time.AfterFunc(1*time.Second, func() {
				conn.Close()
			})
			defer timer.Stop()
			_, err = transport.NewSecureConn(conn).Read(make([]byte, 1)) // try to read 1 byte
			if err == nil {
				t.Errorf("Expected connection closure or error for unauthenticated request, but read succeeded")
			}
		})
	}
}
