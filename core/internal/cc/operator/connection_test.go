package operator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	port := 54321
	OPERATOR_PORT = port

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

	// Test sending a command
	// Mock active agent
	agentTag := "test-agent"
	agent := &def.Emp3r0rAgent{Tag: agentTag}
	live.AgentControlMapMutex.Lock()
	live.AgentControlMap[agent] = &live.AgentControl{
		Index: 0,
		Label: "test-label",
	}
	live.AgentControlMapMutex.Unlock()

	// Mock SendCmd
	originalSendCmd := agents.SendCmd
	defer func() { agents.SendCmd = originalSendCmd }()
	agents.SendCmd = func(cmd, cmd_id string, a *def.Emp3r0rAgent) error {
		t.Logf("Mock SendCmd called: %s", cmd)
		return nil
	}

	cmd := "ls -la"
	cmdID := "test-cmd-id"
	op := def.Operation{
		AgentTag:  agentTag,
		Action:    "command",
		Command:   &cmd,
		CommandID: &cmdID,
	}

	opData, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("Failed to marshal operation: %v", err)
	}

	url = fmt.Sprintf("https://127.0.0.1:%d/%s/%s", port, transport.OperatorRoot, "send_command")
	resp, err = client.Post(url, "application/json", bytes.NewBuffer(opData))
	if err != nil {
		t.Fatalf("Failed to send command: %v", err)
	}
	defer resp.Body.Close()

	t.Logf("Send command response status: %s", resp.Status)

	// We expect 200 OK because we mocked the agent and SendCmd
	if resp.StatusCode != 200 {
		t.Errorf("Expected 200 OK, got %s", resp.Status)
	}
}
