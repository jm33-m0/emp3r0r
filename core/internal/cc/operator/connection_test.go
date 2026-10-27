package operator

import (
	"bytes"
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
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/wireguard"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/server"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

// TestOperatorConnection drives the operator console's HTTP client against the
// real operator service over the WireGuard dialer (host-network fallback in
// tests): it verifies the identity requirement, command dispatch and the
// websocket message tunnel.
func TestOperatorConnection(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "emp3r0r_operator_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	live.EmpWorkSpace = tempDir
	live.EmpConfigFile = filepath.Join(tempDir, "emp3r0r.json")
	transport.EmpWorkSpace = tempDir

	// No userspace WireGuard device is started here, so the dialer and the
	// listener fall back to the host network, both on loopback.
	wireguard.WgServerIP = "127.0.0.1"
	wireguard.WgOperatorIP = "127.0.0.1"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	OperatorPort = port

	go server.StartOperatorServer(port)
	t.Cleanup(func() {
		if network.OperatorServer != nil && network.OperatorServerCtx != nil {
			_ = network.OperatorServer.Shutdown(network.OperatorServerCtx)
		}
	})

	// Give the server some time to start
	time.Sleep(2 * time.Second)

	client := createOperatorHTTPClient()
	if client.Timeout != 0 {
		t.Fatalf("operator client must not set a global timeout for streaming tunnel, got %v", client.Timeout)
	}

	// Mock active agent
	agentTag := "test-agent"
	agent := &def.Emp3r0rAgent{UUID: "test-agent-uuid", Tag: agentTag}
	live.PublishAgent(&live.AgentRecord{Agent: agent, Control: &live.AgentControl{Index: 0}})

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

	sendCommandURL := fmt.Sprintf("http://127.0.0.1:%d/%s/%s", port, transport.OperatorRoot, "send_command")

	// Security assertion: the operator API requires an operator identity. A
	// request without one is rejected.
	anonReq, err := http.NewRequest(http.MethodPost, sendCommandURL, bytes.NewBuffer(opData))
	if err != nil {
		t.Fatalf("Failed to build anonymous request: %v", err)
	}
	anonReq.Header.Set("Content-Type", "application/cbor")
	anonResp, err := client.Do(anonReq)
	if err != nil {
		t.Fatalf("Anonymous request failed: %v", err)
	}
	anonResp.Body.Close()
	if anonResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous request = %d, want 401", anonResp.StatusCode)
	}

	// An identified operator can send a command.
	opReq, err := http.NewRequest(http.MethodPost, sendCommandURL, bytes.NewBuffer(opData))
	if err != nil {
		t.Fatalf("Failed to build command request: %v", err)
	}
	opReq.Header.Set("Content-Type", "application/cbor")
	opReq.Header.Set("operator_session", "test-operator-session")
	resp, err := client.Do(opReq)
	if err != nil {
		t.Fatalf("Failed to send command: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %s", resp.Status)
	}

	// Point the shared operator client at the service and exercise the poll and
	// message-tunnel paths.
	clientpkg.HTTPClient = client
	clientpkg.RootURL = fmt.Sprintf("http://127.0.0.1:%d", port)
	clientpkg.SessionID = "test-operator-session"
	t.Cleanup(func() {
		clientpkg.HTTPClient = nil
		clientpkg.RootURL = ""
		clientpkg.SessionID = ""
	})

	live.PublishAgent(&live.AgentRecord{Agent: &def.Emp3r0rAgent{UUID: "u-poll", Tag: "t-poll", LastSeen: time.Now()}, Control: &live.AgentControl{Index: 0}})
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

	if err := cbor.NewEncoder(msgConn).Encode(&def.OperatorMsg{Tag: "ping"}); err != nil {
		t.Fatalf("Failed to send CBOR frame over websocket tunnel: %v", err)
	}
	_ = msgCtx
}
