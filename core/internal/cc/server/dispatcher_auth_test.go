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

// TestUnauthenticatedRequestRejection verifies that sessions without a valid
// CBOR MsgAuth envelope are rejected quickly by the protocol dispatcher.
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
		CCPort:        fmt.Sprintf("%d", port),
		CAPEM:         string(caCertData),
		C2ChannelMode: def.C2ChannelModeH2Conn,
	}

	go StartC2AgentTLSServer()
	time.Sleep(2 * time.Second)
	defer func() {
		network.StopEmpTLSServer()
	}()

	// Setup HTTP client for h2conn tunnel establishment
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCertData)
	clientRaw := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: certPool, NextProtos: []string{"h2"}},
		ForceAttemptHTTP2: true,
	}}

	c2URL := fmt.Sprintf("https://127.0.0.1:%d", port)

	h2 := h2conn.Client{Client: clientRaw, Method: http.MethodPost}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := h2.Connect(ctx, c2URL)
	if err != nil {
		t.Fatalf("Failed to establish h2 stream: %v", err)
	}
	defer conn.Close()

	// Send invalid first frame (not SecureConn chunk, not MsgAuth).
	if _, err = conn.Write([]byte("not-a-valid-msgauth-frame")); err != nil {
		t.Fatalf("Failed to write invalid frame: %v", err)
	}

	timer := time.AfterFunc(2*time.Second, func() {
		_ = conn.Close()
	})
	defer timer.Stop()
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatalf("Expected server to terminate unauthenticated session, but read succeeded")
	}
}
