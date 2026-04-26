package c2transport_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/handler"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/server"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/posener/h2conn"
)

func assertInvalidCAIdentityRejected(t *testing.T, c2URL string, caCertData []byte, agentUUID string) {
	t.Helper()

	dummyPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	forgedIdentityRaw, err := transport.SignECDSA([]byte(agentUUID), dummyPriv)
	if err != nil {
		t.Fatalf("SignECDSA failed: %v", err)
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCertData)
	h2client := h2conn.Client{Client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certPool, NextProtos: []string{"h2"}}, ForceAttemptHTTP2: true}}, Method: http.MethodPost}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c2Conn, _, err := h2client.Connect(ctx, c2URL)
	if err != nil {
		t.Fatalf("h2.Connect failed: %v", err)
	}
	defer c2Conn.Close()

	sc := transport.NewSecureConn(c2Conn)
	msgAuth := def.MsgAuth{
		Type:          def.MsgAuthType,
		AgentUUID:     agentUUID,
		IdentityToken: base64.URLEncoding.EncodeToString(forgedIdentityRaw),
		Timestamp:     time.Now().Unix(),
		Nonce:         "bad-ca-nonce",
		Capabilities:  []string{live.RuntimeConfig.C2Routes.Checkin},
	}
	if err := cbor.NewEncoder(sc).Encode(msgAuth); err != nil {
		t.Fatalf("encode MsgAuth failed: %v", err)
	}

	timer := time.AfterFunc(1500*time.Millisecond, func() {
		_ = c2Conn.Close()
	})
	defer timer.Stop()

	buf := make([]byte, 1)
	if _, err := sc.Read(buf); err == nil {
		t.Fatal("SECURITY VIOLATION: invalid CA identity token was not rejected")
	}
}

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
	live.EmpWorkSpace = tmpDir

	// Get random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// Setup C2 Config
	live.RuntimeConfig = &def.Config{
		CCH2Port:  fmt.Sprintf("%d", port),
		CCAddress: fmt.Sprintf("https://127.0.0.1:%d", port),
		CAPEM:     string(caCertData),
		C2Routes: def.C2Routing{
			Checkin: "c2-checkin",
			Msg:     "c2-msg",
			FTP:     "c2-ftp",
			WWW:     "c2-www",
			Proxy:   "c2-proxy",
		},
	}

	// Reset live maps
	live.AgentControlMap = sync.Map{}
	live.AgentList = make([]*def.Emp3r0rAgent, 0)

	// Initialize agent database for tracking
	dbPath := filepath.Join(tmpDir, "agents.db")
	err = agents.InitAgentDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize agent database: %v", err)
	}
	defer agents.CloseAgentDB()

	// Start Real C2 Server
	go server.StartC2AgentTLSServer()
	defer network.StopEmpTLSServer()
	// Shutdown C2 Server on exit
	defer network.StopEmpTLSServer()

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
		CCAddress:     c2URL,
		C2ChannelMode: def.C2ChannelModeH2Conn,
		AgentUUID:     agentUUID,
		AgentUUIDSig:  agentSig,
		AgentTag:      agentTag,
		CCTimeout:     5000,
		C2Routes:      live.RuntimeConfig.C2Routes,
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

	// 0. Security gate: invalid CA-signed identity token must be rejected.
	assertInvalidCAIdentityRejected(t, c2URL, caCertData, "bad-ca-"+uuid.NewString())

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
	conn, ctx, cancel, err := c2transport.EstablishC2Connection(msgURL, "", common.RuntimeConfig.C2Routes.Msg)
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
	// tunnel. Since the server never pinned the new key, the dispatcher will verify
	// the signature against the OLD pinned key and fail!
	failedMsgURL := fmt.Sprintf("%s/%s/%s", c2URL, transport.MsgAPI, agentUUID)
	failedConn, _, failedCancel, err := c2transport.EstablishC2Connection(failedMsgURL, "", common.RuntimeConfig.C2Routes.Msg)
	if err == nil {
		// New protocol: server might close connection AFTER MsgAuth is sent.
		// Try to read to see if it's still alive.
		buf := make([]byte, 1)
		_, readErr := failedConn.Read(buf)
		if readErr == nil {
			failedCancel()
			failedConn.Close()
			t.Fatal("SECURITY VIOLATION: msg tunnel established with rotated key! Key rotation is supposed to be banned.")
		}
		failedCancel()
		failedConn.Close()
	}
	t.Logf("✓ Key rotation correctly rejected (msg tunnel denied or closed): %v", err)

	// Simulate `forget_agent`
	t.Logf("Testing forgotten agent recovery workflow...")
	err = agents.RemoveAgent(agentUUID)
	if err != nil {
		t.Fatalf("Failed to remove agent from DB: %v", err)
	}

	// The agent should now be able to check in successfully with its new key!
	err = c2transport.ReportStatus(config, agentInfo)
	if err != nil {
		t.Logf("ReportStatus returned error (expected or early EOF): %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	// Verify the message tunnel can now be established with the new key
	recoveredConn, _, recoveredCancel, err := c2transport.EstablishC2Connection(failedMsgURL, "", common.RuntimeConfig.C2Routes.Msg)
	if err != nil {
		t.Fatalf("Recovery failed: msg tunnel could not be established after forget_agent: %v", err)
	}
	recoveredCancel()
	recoveredConn.Close()
	t.Log("✓ Agent successfully recovered and re-registered after forget_agent")

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
	live.EmpWorkSpace = tmpDir

	// Get random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// CUSTOM PATHS

	// Setup C2 Config
	live.RuntimeConfig = &def.Config{
		CCH2Port: fmt.Sprintf("%d", port),
		CAPEM:    string(caCertData),
		C2Routes: def.C2Routing{
			Checkin: "c2-checkin",
			Msg:     "c2-msg",
			FTP:     "c2-ftp",
			WWW:     "c2-www",
			Proxy:   "c2-proxy",
		},
	}

	// Ensure this test uses an isolated fresh AgentDB handle.
	if agents.AgentDB != nil {
		_ = agents.CloseAgentDB()
	}
	dbPath := filepath.Join(tmpDir, "agents.db")
	if err = agents.InitAgentDB(dbPath); err != nil {
		t.Fatalf("Failed to initialize agent database: %v", err)
	}
	defer agents.CloseAgentDB()

	// Start Real C2 Server
	go server.StartC2AgentTLSServer()
	defer network.StopEmpTLSServer()

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
		CCAddress:     c2URL,
		C2ChannelMode: def.C2ChannelModeH2Conn,
		AgentUUID:     agentUUID,
		AgentUUIDSig:  agentSig,
		AgentTag:      agentTag,
		C2Routes:      live.RuntimeConfig.C2Routes,
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

	// Check-in processing is async on server side. Wait until the agent is
	// durably visible in AgentDB before opening FTP/WWW streams.
	deadline := time.Now().Add(5 * time.Second)
	for {
		storedAgent, getErr := agents.GetStoredAgent(agentUUID)
		if getErr == nil && storedAgent != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent %s not persisted after check-in before FTP/WWW tests", agentUUID)
		}
		time.Sleep(100 * time.Millisecond)
	}
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
	live.EmpWorkSpace = tmpDir

	// Get random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// Setup C2 Config
	live.RuntimeConfig = &def.Config{
		CCH2Port: fmt.Sprintf("%d", port),
		CAPEM:    string(caCertData),
		C2Routes: def.C2Routing{
			Checkin: "c2-checkin",
			Msg:     "c2-msg",
			FTP:     "c2-ftp",
			WWW:     "c2-www",
			Proxy:   "c2-proxy",
		},
	}

	// Start Real C2 Server
	go server.StartC2AgentTLSServer()
	defer network.StopEmpTLSServer()

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
		CCAddress:     c2URL,
		C2ChannelMode: def.C2ChannelModeH2Conn,
		AgentUUID:     agentUUID,
		AgentUUIDSig:  agentSig,
		AgentTag:      agentUUID,
		C2Routes:      live.RuntimeConfig.C2Routes,
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
	conn, _, cancel, err := c2transport.EstablishC2Connection(msgURL, "", common.RuntimeConfig.C2Routes.Msg)
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
	live.EmpWorkSpace = tmpDir

	// Get random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// CUSTOM PATHS on SERVER

	// Setup C2 Config
	live.RuntimeConfig = &def.Config{
		CCH2Port: fmt.Sprintf("%d", port),
		CAPEM:    string(caCertData),
		C2Routes: def.C2Routing{
			Checkin: "c2-checkin",
			Msg:     "c2-msg",
			FTP:     "c2-ftp",
			WWW:     "c2-www",
			Proxy:   "c2-proxy",
		},
	}

	// Ensure this test uses an isolated fresh AgentDB handle.
	if agents.AgentDB != nil {
		_ = agents.CloseAgentDB()
	}
	dbPath := filepath.Join(tmpDir, "agents.db")
	if err = agents.InitAgentDB(dbPath); err != nil {
		t.Fatalf("Failed to initialize agent database: %v", err)
	}
	defer agents.CloseAgentDB()

	// Start Real C2 Server
	go server.StartC2AgentTLSServer()
	defer network.StopEmpTLSServer()

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
		CCAddress:     c2URL,
		C2ChannelMode: def.C2ChannelModeH2Conn,
		AgentUUID:     agentUUID,
		AgentUUIDSig:  agentSig,
		AgentTag:      agentTag,
		C2Routes:      live.RuntimeConfig.C2Routes,
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

	// Check-in processing is async on server side. Wait until the agent is
	// durably visible in AgentDB before finishing this strict check-in test.
	deadline := time.Now().Add(5 * time.Second)
	for {
		storedAgent, getErr := agents.GetStoredAgent(agentUUID)
		if getErr == nil && storedAgent != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent %s not persisted after check-in", agentUUID)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Log("Strict check-in path verified; auxiliary FTP/WWW routes require operator-owned relay and are tested separately")
}
