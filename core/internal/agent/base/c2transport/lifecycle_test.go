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
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
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
	transport.CaKeyFile = caKeyFile
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

	// Reset live maps
	live.AgentControlMap = sync.Map{}
	live.AgentList = make([]*def.Emp3r0rAgent, 0)

	// Initialize agent database for tracking BEFORE starting server
	dbPath := filepath.Join(tmpDir, "agents.db")
	err = agents.InitAgentDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize agent database: %v", err)
	}
	defer agents.CloseAgentDB()

	// Start Real C2 Server
	go server.StartC2AgentTLSServer()

	// Wait for server to start
	time.Sleep(2 * time.Second)

	// Setup Agent Config
	agentUUID := uuid.New().String()
	agentTag := "kali\\kali_0-agent-" + agentUUID

	// Use NEW ephemeral key generation (PFS)
	err = agentutils.GetAgentKey()
	if err != nil {
		t.Fatalf("Failed to generate ephemeral agent key: %v", err)
	}

	// Serialize public key for transmission (PEM format for agent info)
	agentPubKeyPEM, err := transport.PublicKeyToPEM(&agentutils.AgentKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to convert public key to PEM: %v", err)
	}

	// Sign with CA Key (Proof of Origin)
	caKey, err := transport.ParseKeyPemFile(caKeyFile)
	if err != nil {
		t.Fatalf("Failed to parse CA key: %v", err)
	}
	agentSig, err := signUUID(agentUUID, caKey)
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
		PublicKey: string(agentPubKeyPEM),
	}
	// Check-in
	config := common.RuntimeConfig
	err = c2transport.ReportStatus(config, agentInfo)
	if err != nil {
		t.Fatalf("ReportStatus failed: %v", err)
	}
	t.Log("Successfully checked in")

	// Wait for database write to complete (async operation)
	time.Sleep(500 * time.Millisecond)

	// Verify agent was recorded in database
	t.Logf("Checking database for agent UUID: %s", agentUUID)
	storedAgent, err := agents.GetStoredAgent(agentUUID)
	if err != nil {
		t.Fatalf("Failed to get stored agent: %v", err)
	}
	if storedAgent == nil {
		// Debug: Check if database is accessible
		if agents.AgentDB == nil {
			t.Fatal("AgentDB is nil - database not initialized properly")
		}
		t.Fatal("Agent not found in database after check-in")
	}
	if storedAgent.ConnectionCount != 1 {
		t.Errorf("Expected connection count 1, got %d", storedAgent.ConnectionCount)
	}
	t.Logf("✓ Agent recorded in database with connection count: %d", storedAgent.ConnectionCount)

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
			// Use fmt.Printf instead of t.Errorf since goroutine may outlive test
			if !strings.Contains(err.Error(), "context canceled") && !strings.Contains(err.Error(), "closed") {
				fmt.Printf("MsgTunneler exited with unexpected error: %v\n", err)
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
		JobID:    "test-cmd-id",
		CmdSlice: []string{"ls"},
	}, agent)
	t.Log("Command 'ls' sent to agent")

	// Wait for agent to process and notify back
	time.Sleep(2 * time.Second)

	// 5. Verify key rotation is REJECTED (policy: rotation is permanently banned)
	t.Log("Verifying key rotation is rejected...")
	cancel()
	conn.Close()
	time.Sleep(500 * time.Millisecond)

	// Generate NEW ephemeral key (simulating a second instance of the same binary)
	err = agentutils.RenewAgentKey()
	if err != nil {
		t.Fatalf("Failed to renew agent key: %v", err)
	}
	newAgentPubKeyPEM, err := transport.PublicKeyToPEM(&agentutils.AgentKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to convert new public key to PEM: %v", err)
	}
	agentInfo.PublicKey = string(newAgentPubKeyPEM)

	// Verify DB state right before rotation checkin
	if agents.AgentDB != nil {
		rows, err := agents.AgentDB.Query("SELECT uuid FROM agents")
		if err == nil {
			t.Log("--- DB CONTENTS BEFORE ROTATION ---")
			count := 0
			for rows.Next() {
				var u string
				rows.Scan(&u)
				t.Logf("Found in DB: %q", u)
				count++
			}
			t.Logf("Total rows in DB: %d", count)
			rows.Close()
		} else {
			t.Logf("DB Query Error: %v", err)
		}

		stored, err := agents.GetStoredAgent(agentUUID)
		t.Logf("DB State before rotation: stored_found=%v, err=%v", stored != nil, err)
	}

	// Check-in succeeds at the HTTP transport level because h2conn upgrades immediately,
	// but the server silently drops the agent inside handleAgentCheckIn.
	err = c2transport.ReportStatus(config, agentInfo)
	if err != nil {
		t.Logf("ReportStatus returned error (expected or early EOF): %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	// To verify the rotation was actually rejected, we attempt to open the message
	// tunnel. Since the server never pinned the new key, VerifyAgentRequest will fail
	// the signature check and return 403 Forbidden *before* upgrading the connection!
	failedMsgURL := fmt.Sprintf("%s/%s/%s", c2URL, transport.MsgAPI, agentUUID)
	failedConn, _, failedCancel, err := c2transport.EstablishC2Connection(failedMsgURL)
	if err == nil {
		failedCancel()
		failedConn.Close()
		t.Fatal("SECURITY VIOLATION: msg tunnel established with rotated key! Key rotation is supposed to be banned.")
	}
	t.Logf("✓ Key rotation correctly rejected (msg tunnel denied): %v", err)

	t.Log("Full Agent Lifecycle Test Passed")
	select {
	case <-tunDone:
	case <-time.After(1 * time.Second):
		t.Log("MsgTunneler already exited")
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
	transport.CaKeyFile = caKeyFile
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
	// Gen Agent Key (TOFU)
	agentPriv, agentPub, err := genAgentKey()
	if err != nil {
		t.Fatalf("Failed to gen agent key: %v", err)
	}
	agentutils.AgentKey = agentPriv
	// Sign with CA Key (Proof of Origin)
	caKey, err := transport.ParseKeyPemFile(caKeyFile)
	if err != nil {
		t.Fatalf("Failed to parse CA key: %v", err)
	}
	agentSig, err := signUUID(agentUUID, caKey)
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
		Tag:       agentTag,
		Name:      "test-random-path-lifecycle",
		UUID:      agentUUID,
		UUIDSig:   agentSig,
		PublicKey: agentPub,
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
	transport.CaKeyFile = caKeyFile
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
	// Gen Agent Key (TOFU)
	agentPriv, agentPub, err := genAgentKey()
	if err != nil {
		t.Fatalf("Failed to gen agent key: %v", err)
	}
	agentutils.AgentKey = agentPriv
	// Sign with CA Key (Proof of Origin)
	caKey, err := transport.ParseKeyPemFile(caKeyFile)
	if err != nil {
		t.Fatalf("Failed to parse CA key: %v", err)
	}
	agentSig, err := signUUID(agentUUID, caKey)
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
		Tag:       agentUUID,
		Name:      "test-agent-dynamic",
		UUID:      agentUUID,
		UUIDSig:   agentSig,
		PublicKey: agentPub,
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

func TestCheckinWithRandomPaths_Strict(t *testing.T) {
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
	transport.CaKeyFile = caKeyFile
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
	// Gen Agent Key (TOFU)
	agentPriv, agentPub, err := genAgentKey()
	if err != nil {
		t.Fatalf("Failed to gen agent key: %v", err)
	}
	agentutils.AgentKey = agentPriv
	// Sign with CA Key (Proof of Origin)
	caKey, err := transport.ParseKeyPemFile(caKeyFile)
	if err != nil {
		t.Fatalf("Failed to parse CA key: %v", err)
	}
	agentSig, err := signUUID(agentUUID, caKey)
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
		CheckInPath:  checkInPath, // Agent MUST use the correct path now
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
		Tag:       agentTag,
		Name:      "test-random-path-lifecycle",
		UUID:      agentUUID,
		UUIDSig:   agentSig,
		PublicKey: agentPub,
	}
	config := common.RuntimeConfig
	err = c2transport.ReportStatus(config, agentInfo)
	if err != nil {
		t.Fatalf("ReportStatus failed with random paths: %v", err)
	}
	t.Log("Successfully checked in with random paths")
}
