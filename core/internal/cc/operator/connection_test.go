package operator

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	clientpkg "github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/config"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/server"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
)

func TestOperatorConnection(t *testing.T) {
	// Setup temporary workspace
	tempDir, err := os.MkdirTemp("", "emp3r0r_operator_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Update live.EmpWorkSpace
	live.EmpWorkSpace = tempDir
	live.EmpConfigFile = filepath.Join(tempDir, "emp3r0r.json")

	// Update transport paths
	transport.EmpWorkSpace = tempDir
	transport.CaCrtFile = filepath.Join(tempDir, "ca-cert.pem")
	transport.CaKeyFile = filepath.Join(tempDir, "ca-key.pem")
	transport.ServerCrtFile = filepath.Join(tempDir, "server-cert.pem")
	transport.ServerKeyFile = filepath.Join(tempDir, "server-key.pem")
	transport.OperatorCaCrtFile = filepath.Join(tempDir, "operator-ca-cert.pem")
	transport.OperatorCaKeyFile = filepath.Join(tempDir, "operator-ca-key.pem")
	transport.OperatorServerCrtFile = filepath.Join(tempDir, "operator-server-cert.pem")
	transport.OperatorServerKeyFile = filepath.Join(tempDir, "operator-server-key.pem")
	transport.OperatorClientCrtFile = filepath.Join(tempDir, "operator-client-cert.pem")
	transport.OperatorClientKeyFile = filepath.Join(tempDir, "operator-client-key.pem")

	// Set WireGuard IP to localhost for testing
	netutil.WgServerIP = "127.0.0.1"
	netutil.WgOperatorIP = "127.0.0.1"

	// Set IsServer to true so InitCertsAndConfig generates certs
	live.IsServer = true

	// Initialize certs and config
	// This generates OperatorClientCrtFile and OperatorCaCrtFile
	err = config.InitCertsAndConfig()
	if err != nil {
		t.Fatalf("InitCertsAndConfig failed: %v", err)
	}

	// Generate C2 certs (including OperatorServerCrtFile)
	err = config.GenC2Certs("127.0.0.1")
	if err != nil {
		t.Fatalf("GenC2Certs failed: %v", err)
	}

	// Pick a random port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	OperatorPort = port

	// Start Operator mTLS Server
	go func() {
		server.StartOperatorMTLSServer(port)
	}()

	// Give the server some time to start
	time.Sleep(2 * time.Second)

	// Create mTLS HTTP client
	client, err := createMTLSHttpClient()
	if err != nil {
		t.Fatalf("createMTLSHttpClient failed: %v", err)
	}
	if client.Timeout != 0 {
		t.Fatalf("createMTLSHttpClient must not set a global timeout for streaming tunnel, got %v", client.Timeout)
	}

	// Test connection
	// The server exposes /emp3r0r/api
	// We can try to hit a non-existent endpoint to check connectivity,
	// or a valid one if we know it.
	// operationDispatcher handles /{api}

	url := fmt.Sprintf("https://127.0.0.1:%d/%s/checkin", port, transport.OperatorRoot)
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("Failed to connect to operator server: %v", err)
	}
	defer resp.Body.Close()

	// We expect 404 or 200, but not a connection error
	// Since "checkin" might not be a valid API handler or might require POST
	t.Logf("Response status: %s", resp.Status)

	// Mock active agent
	agentTag := "test-agent"
	agent := &def.Emp3r0rAgent{Tag: agentTag}
	live.AgentControlMap.Store(agent, &live.AgentControl{
		Index: 0,
		Label: "test-label",
	})

	// Mock SendCmd
	originalSendCmd := agents.SendCmd
	defer func() { agents.SendCmd = originalSendCmd }()
	agents.SendCmd = func(cmd, job_id string, a *def.Emp3r0rAgent) error {
		t.Logf("Mock SendCmd called: %s", cmd)
		return nil
	}

	cmd := "ls -la"
	cmdID := "test-cmd-id"
	op := def.Operation{
		AgentTag: agentTag,
		Action:   "command",
		Command:  &cmd,
		JobID:    &cmdID,
	}

	opData, err := cbor.Marshal(op)
	if err != nil {
		t.Fatalf("Failed to marshal operation: %v", err)
	}

	url = fmt.Sprintf("https://127.0.0.1:%d/%s/%s", port, transport.OperatorRoot, "send_command")
	resp, err = client.Post(url, "application/cbor", bytes.NewBuffer(opData))
	if err != nil {
		t.Fatalf("Failed to send command: %v", err)
	}
	defer resp.Body.Close()

	t.Logf("Send command response status: %s", resp.Status)

	// We expect 200 OK because we mocked the agent and SendCmd
	if resp.StatusCode != 200 {
		t.Errorf("Expected 200 OK, got %s", resp.Status)
	}

	// Security assertion: operator endpoint must require mTLS client certs.
	operatorCAPEM, err := os.ReadFile(transport.OperatorCaCrtFile)
	if err != nil {
		t.Fatalf("Failed to read operator CA cert: %v", err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(operatorCAPEM) {
		t.Fatal("Failed to append operator CA cert to pool")
	}
	unauthorizedClient := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: rootCAs},
		},
	}
	_, err = unauthorizedClient.Get(fmt.Sprintf("https://127.0.0.1:%d/%s/checkin", port, transport.OperatorRoot))
	if err == nil {
		t.Fatal("SECURITY VIOLATION: operator endpoint accepted a client without mTLS certificate")
	}

	// Verify the websocket operator message tunnel also connects over the same mTLS trust root.
	clientpkg.HTTPClient = client
	clientpkg.RootURL = fmt.Sprintf("https://127.0.0.1:%d", port)
	clientpkg.SessionID = "test-operator-session"

	// Verify the agent-list poll path (list_connected_agents) round-trips
	// LastSeen correctly.
	live.AgentControlMap.Store(&def.Emp3r0rAgent{UUID: "u-poll", Tag: "t-poll", LastSeen: time.Now()}, &live.AgentControl{Index: 0})
	pollAgents, pollErr := clientpkg.GetAgentList()
	if pollErr != nil {
		t.Fatalf("GetAgentList failed: %v", pollErr)
	}
	if len(pollAgents) == 0 {
		t.Fatal("GetAgentList returned no agents")
	}
	for _, a := range pollAgents {
		t.Logf("GetAgentList: %s LastSeen=%v (%.0fs ago)", a.Tag, a.LastSeen, time.Since(a.LastSeen).Seconds())
	}

	msgConn, msgCtx, msgCancel, err := clientpkg.ConnectMsgTun()
	if err != nil {
		t.Fatalf("ConnectMsgTun failed: %v", err)
	}
	defer msgCancel()
	defer msgConn.Close()

	if err := cbor.NewEncoder(msgConn).Encode(&def.MsgTunData{Tag: "ping"}); err != nil {
		t.Fatalf("Failed to send CBOR frame over websocket tunnel: %v", err)
	}
	_ = msgCtx
}
