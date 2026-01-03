package c2transport

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/posener/h2conn"
)

func TestConnectCC(t *testing.T) {
	// Setup temp dir for certs
	tmpDir, err := os.MkdirTemp("", "emp3r0r_test")
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

	// Read CA cert
	caCertData, err := os.ReadFile(caCertFile)
	if err != nil {
		t.Fatalf("Failed to read CA cert: %v", err)
	}
	transport.CACrtPEM = caCertData

	// Start Mock C2 Server
	server := &http.Server{
		Addr: "127.0.0.1:0", // Random port
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Accept h2conn
			conn, err := h2conn.Accept(w, r)
			if err != nil {
				t.Logf("Failed to accept h2conn: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			defer conn.Close()
			t.Logf("Accepted connection from %s", r.RemoteAddr)

			// Read message
			buf := make([]byte, 4)
			_, err = conn.Read(buf)
			if err != nil {
				t.Errorf("Failed to read: %v", err)
				return
			}
			if string(buf) != "ping" {
				t.Errorf("Expected 'ping', got '%s'", string(buf))
				return
			}

			// Send response
			_, err = conn.Write([]byte("pong"))
			if err != nil {
				t.Errorf("Failed to write: %v", err)
				return
			}
		}),
	}

	// Load server certs
	cert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		t.Fatalf("Failed to load server key pair: %v", err)
	}

	server.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		if err := server.ServeTLS(listener, "", ""); err != nil && err != http.ErrServerClosed {
			t.Logf("Server error: %v", err)
		}
	}()
	defer server.Close()

	// Get server address
	serverAddr := listener.Addr().String()
	c2URL := fmt.Sprintf("https://%s", serverAddr)
	t.Logf("Mock C2 Server listening on %s", c2URL)

	// Setup Agent Config
	common.RuntimeConfig = &def.Config{
		CCAddress: c2URL,
		AgentUUID: "test-agent-uuid",
	}

	// Initialize HTTP Client
	// We need to set def.HTTPClient manually as agent_main does
	def.HTTPClient = transport.CreateEmp3r0rHTTPClient(c2URL, "")

	// Test ConnectCC
	conn, _, cancel, err := ConnectCC(c2URL)
	if err != nil {
		t.Fatalf("ConnectCC failed: %v", err)
	}
	defer cancel()
	defer conn.Close()

	t.Log("Successfully connected to C2")

	// Send ping
	_, err = conn.Write([]byte("ping"))
	if err != nil {
		t.Fatalf("Failed to write ping: %v", err)
	}

	// Read pong
	buf := make([]byte, 4)
	_, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read pong: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("Expected 'pong', got '%s'", string(buf))
	}
	t.Log("Successfully exchanged ping/pong")
}
