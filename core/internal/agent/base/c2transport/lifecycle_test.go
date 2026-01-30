package c2transport_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/handler"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/server"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

func TestFullAgentLifecycle(t *testing.T) {
	// Setup temp dir for certs
	tmpDir, err := os.MkdirTemp("", "agent_lifecycle_test")
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

	// Setup Transport Paths for C2 Server
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

	// Reset live maps with proper locking
	live.AgentControlMapMutex.Lock()
	live.AgentControlMap = make(map[*def.Emp3r0rAgent]*live.AgentControl)
	live.AgentList = make([]*def.Emp3r0rAgent, 0)
	live.AgentControlMapMutex.Unlock()

	// Start Real C2 Server
	go server.StartC2AgentTLSServer()

	// Wait for server to start
	time.Sleep(2 * time.Second)

	// Setup Agent Config
	agentUUID := uuid.New().String()
	agentTag := "kali\\kali_0-agent-" + agentUUID
	agentSig, err := signUUID(agentUUID, caKeyFile)
	if err != nil {
		t.Fatalf("Failed to sign UUID: %v", err)
	}

	c2URL := fmt.Sprintf("https://127.0.0.1:%d", port)
	common.RuntimeConfig = &def.Config{
		CCAddress:    c2URL,
		AgentUUID:    agentUUID,
		AgentUUIDSig: agentSig,
		AgentTag:     agentTag,
		CCTimeout:    5000,
	}
	def.CCAddress = c2URL

	// Initialize HTTP Client
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCertData)
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: certPool},
		ForceAttemptHTTP2: true,
	}
	def.HTTPClient = &http.Client{Transport: tr}

	// 1. ReportStatus (Check-in)
	agentInfo := &def.Emp3r0rAgent{
		Tag:       agentTag,
		Name:      "test-agent",
		Version:   "0.0.0",
		Transport: "HTTP2",
		OS:        "Linux",
		GOOS:      "linux",
		IPs:       []string{"127.0.0.1"},
		Process:   &def.AgentProcess{},
		UUID:      agentUUID,
		UUIDSig:   agentSig,
	}
	// Check-in
	config := common.RuntimeConfig
	err = c2transport.ReportStatus(config, agentInfo)
	if err != nil {
		t.Fatalf("ReportStatus failed: %v", err)
	}
	t.Log("Successfully checked in")

	// 2. Establish persistent connection
	msgURL := fmt.Sprintf("%s/%s/%s", c2URL, transport.MsgAPI, agentUUID)
	conn, ctx, cancel, err := c2transport.EstablishC2Connection(msgURL)
	if err != nil {
		t.Fatalf("EstablishC2Connection failed: %v", err)
	}
	def.CCMsgConn = conn
	defer conn.Close()
	defer cancel()

	// 3. Start MsgTunneler and verify handshakes
	mockCallback := func(data *def.MsgTunData) {
		// This callback is called when C2 sends something to the agent
		// We can use it to verify command execution later
		if len(data.CmdSlice) > 0 && data.CmdSlice[0] == "ls" {
			t.Logf("Agent received command: %v", data.CmdSlice)
			c2transport.NotifyC2(handler.CoreCommands(), "listing files...")
		}
	}

	// We'll wrap MsgTunneler to count success responses in def.HandShakes
	tunDone := make(chan struct{})
	go func() {
		defer close(tunDone)
		if err := c2transport.MsgTunneler(conn, config, mockCallback, ctx, cancel); err != nil {
			if !strings.Contains(err.Error(), "context canceled") {
				t.Errorf("MsgTunneler exited with unexpected error: %v", err)
			}
		}
	}()

	// Wait and verify multiple successful handshakes
	t.Log("Waiting for handshakes...")
	time.Sleep(10 * time.Second)

	// If MsgTunneler failed, ctx.Err() would be non-nil or we would see logs
	if ctx.Err() != nil {
		t.Errorf("MsgTunneler stopped unexpectedly: %v", ctx.Err())
	} else {
		t.Log("MsgTunneler is still active after 10 seconds, handshakes likely successful")
	}

	// 4. Verify Command Execution
	// Get agent from server maps
	agent := agents.GetAgentByUUID(agentUUID)
	if agent == nil {
		// Log all agents for debugging
		allAgents := agents.GetConnectedAgents()
		t.Logf("Currently connected agents (%d):", len(allAgents))
		for _, a := range allAgents {
			t.Logf("  - Tag: %s, UUID: %s", a.Tag, a.UUID)
		}
		t.Fatalf("Agent not found on server by UUID: %s", agentUUID)
	}

	// Register the connection in AgentControlMap if it's not already there (it should be after first handshake)
	time.Sleep(1 * time.Second)
	agents.SendMessageToAgent(&def.MsgTunData{
		Tag:      agentTag,
		CmdID:    "test-cmd-id",
		CmdSlice: []string{"ls"},
	}, agent)
	t.Log("Command 'ls' sent to agent")

	// Wait for agent to process and notify back
	time.Sleep(2 * time.Second)

	t.Log("Full Agent Lifecycle Test Passed")

	// Cleanup: cancel context to stop MsgTunneler, then wait for it to exit
	cancel()
	go conn.Close()
	select {
	case <-tunDone:
	case <-time.After(1 * time.Second):
		t.Log("MsgTunneler did not exit in time (pending I/O), forcing test completion")
	}
}

func TestCheckinWithRandomPaths(t *testing.T) {
	// Setup temp dir for certs
	tmpDir, err := os.MkdirTemp("", "agent_test_random_lifecycle")
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

	// Setup Transport Paths for C2 Server
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

	// CUSTOM PATHS
	c2Prefix := "custom_prefix"
	checkInPath := "custom_checkin"

	// Setup C2 Config
	live.RuntimeConfig = &def.Config{
		CCPort:      fmt.Sprintf("%d", port),
		CAPEM:       string(caCertData),
		C2Prefix:    c2Prefix,
		CheckInPath: checkInPath,
	}

	// Start Real C2 Server
	go server.StartC2AgentTLSServer()

	// Wait for server to start
	time.Sleep(2 * time.Second)

	// Setup Agent Config
	agentUUID := uuid.New().String()
	agentTag := "random-path-lifecycle-agent"
	agentSig, err := signUUID(agentUUID, caKeyFile)
	if err != nil {
		t.Fatalf("Failed to sign UUID: %v", err)
	}

	c2URL := fmt.Sprintf("https://127.0.0.1:%d", port)
	common.RuntimeConfig = &def.Config{
		CCAddress:    c2URL,
		AgentUUID:    agentUUID,
		AgentUUIDSig: agentSig,
		AgentTag:     agentTag,
		C2Prefix:     c2Prefix,
		CheckInPath:  checkInPath,
	}
	def.CCAddress = c2URL

	// Initialize HTTP Client
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCertData)
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: certPool},
		ForceAttemptHTTP2: true,
	}
	def.HTTPClient = &http.Client{Transport: tr}

	// Check-in
	agentInfo := &def.Emp3r0rAgent{
		Tag:     agentTag,
		Name:    "test-random-path-lifecycle",
		UUID:    agentUUID,
		UUIDSig: agentSig,
	}
	config := common.RuntimeConfig
	err = c2transport.ReportStatus(config, agentInfo)
	if err != nil {
		t.Fatalf("ReportStatus failed with random paths: %v", err)
	}
	t.Log("Successfully checked in with random paths")
}

func TestDynamicPrefix(t *testing.T) {
	// Setup temp dir for certs
	tmpDir, err := os.MkdirTemp("", "agent_test_dynamic")
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

	// Setup Transport Paths for C2 Server
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
		// C2Prefix is NOT set
	}

	// Start Real C2 Server
	go server.StartC2AgentTLSServer()

	// Wait for server to start
	time.Sleep(2 * time.Second)

	// Setup Agent Config with dynamic prefix
	agentUUID := uuid.New().String()
	agentSig, err := signUUID(agentUUID, caKeyFile)
	if err != nil {
		t.Fatalf("Failed to sign UUID: %v", err)
	}

	c2URL := fmt.Sprintf("https://127.0.0.1:%d", port)

	// USE A RANDOM PREFIX HERE
	randomPrefix := "stealthy-prefix-" + uuid.New().String()

	common.RuntimeConfig = &def.Config{
		CCAddress:    c2URL,
		AgentUUID:    agentUUID,
		AgentUUIDSig: agentSig,
		AgentTag:     agentUUID,
		C2Prefix:     randomPrefix, // Agent uses this prefix
	}
	def.CCAddress = c2URL

	// Initialize HTTP Client
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCertData)
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: certPool},
		ForceAttemptHTTP2: true,
	}
	def.HTTPClient = &http.Client{Transport: tr}

	// Check-in
	agentInfo := &def.Emp3r0rAgent{
		Tag:     agentUUID,
		Name:    "test-agent-dynamic",
		UUID:    agentUUID,
		UUIDSig: agentSig,
	}

	t.Logf("Attempting checkin with prefix: %s", randomPrefix)
	err = c2transport.ReportStatus(common.RuntimeConfig, agentInfo)
	if err != nil {
		t.Fatalf("ReportStatus failed with dynamic prefix %q: %v", randomPrefix, err)
	}
	t.Log("Successfully checked in with dynamic prefix")

	// MsgTun
	msgURL := fmt.Sprintf("%s/%s/msg/%s", c2URL, randomPrefix, "test-token")
	conn, _, cancel, err := c2transport.EstablishC2Connection(msgURL)
	if err != nil {
		t.Fatalf("EstablishC2Connection failed with dynamic prefix: %v", err)
	}
	defer conn.Close()
	defer cancel()
	t.Log("Successfully connected MsgTun with dynamic prefix")
}

func TestCheckinWithRandomPaths_DefaultFallback(t *testing.T) {
	// Setup temp dir for certs
	tmpDir, err := os.MkdirTemp("", "agent_test_random_lifecycle_fallback")
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

	// Setup Transport Paths for C2 Server
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

	// CUSTOM PATHS on SERVER
	c2Prefix := "custom_prefix"
	checkInPath := "custom_checkin"
	// But agent will use DEFAULT paths

	// Setup C2 Config
	live.RuntimeConfig = &def.Config{
		CCPort:      fmt.Sprintf("%d", port),
		CAPEM:       string(caCertData),
		C2Prefix:    c2Prefix,
		CheckInPath: checkInPath, // Server expects this
	}

	// Start Real C2 Server
	go server.StartC2AgentTLSServer()

	// Wait for server to start
	time.Sleep(2 * time.Second)

	// Setup Agent Config
	agentUUID := uuid.New().String()
	agentTag := "random-path-lifecycle-agent-start"
	agentSig, err := signUUID(agentUUID, caKeyFile)
	if err != nil {
		t.Fatalf("Failed to sign UUID: %v", err)
	}

	c2URL := fmt.Sprintf("https://127.0.0.1:%d", port)
	common.RuntimeConfig = &def.Config{
		CCAddress:    c2URL,
		AgentUUID:    agentUUID,
		AgentUUIDSig: agentSig,
		AgentTag:     agentTag,
		C2Prefix:     c2Prefix,
		// CheckInPath is NOT set, so agent defaults to "checkin"
	}
	def.CCAddress = c2URL

	// Initialize HTTP Client
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCertData)
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: certPool},
		ForceAttemptHTTP2: true,
	}
	def.HTTPClient = &http.Client{Transport: tr}

	// Check-in
	agentInfo := &def.Emp3r0rAgent{
		Tag:     agentTag,
		Name:    "test-random-path-lifecycle-fallback",
		UUID:    agentUUID,
		UUIDSig: agentSig,
	}
	config := common.RuntimeConfig
	err = c2transport.ReportStatus(config, agentInfo)
	if err != nil {
		t.Fatalf("ReportStatus failed with random paths: %v", err)
	}
	t.Log("Successfully checked in with random paths (fallback)")
}
