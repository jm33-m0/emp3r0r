package c2transport_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/handler"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/server"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
)

func signUUID(uuid string, keyFile string) (string, error) {
	// Read private key
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(keyBytes)
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	// Hash UUID
	hash := sha256.Sum256([]byte(uuid))

	// Sign
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return "", err
	}

	// Encode signature
	sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(sig), nil
}

func TestEstablishC2Connection(t *testing.T) {
	// Setup temp dir for certs
	tmpDir, err := os.MkdirTemp("", "agent_test")
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
	transport.OperatorCaCrtFile = caCertFile // Set OperatorCaCrtFile for apiDispatcher
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

	// Start Real C2 Server
	go server.StartC2AgentTLSServer()

	// Wait for server to start
	time.Sleep(2 * time.Second)

	// Setup Agent Config
	agentUUID := "test-agent-uuid"
	agentSig, err := signUUID(agentUUID, caKeyFile)
	if err != nil {
		t.Fatalf("Failed to sign UUID: %v", err)
	}

	c2URL := fmt.Sprintf("https://127.0.0.1:%d", port)
	common.RuntimeConfig = &def.Config{
		CCAddress:    c2URL,
		AgentUUID:    agentUUID,
		AgentUUIDSig: agentSig,
		AgentTag:     agentUUID, // Set AgentTag to match UUID for test
		CCTimeout:    10000,     // Set timeout to 10 seconds
	}
	def.CCAddress = c2URL // Set global CCAddress for ReportStatus

	// Initialize HTTP Client manually to avoid utls issues in test
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(caCertData); !ok {
		t.Fatalf("Failed to append CA cert")
	}

	tlsConfig := &tls.Config{
		RootCAs:            certPool,
		InsecureSkipVerify: false,
	}

	tr := &http.Transport{
		TLSClientConfig:   tlsConfig,
		ForceAttemptHTTP2: true,
	}
	def.HTTPClient = &http.Client{Transport: tr}

	// ReportStatus
	agentInfo := &def.Emp3r0rAgent{
		Tag:       agentUUID,
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
	err = c2transport.ReportStatus(agentInfo)
	if err != nil {
		t.Fatalf("ReportStatus failed: %v", err)
	}
	t.Log("Successfully checked in")

	// Construct MsgAPI URL
	msgURL := fmt.Sprintf("%s/%s/%s", c2URL, transport.MsgAPI, "test-token")

	// Test EstablishC2Connection
	conn, ctx, cancel, err := c2transport.EstablishC2Connection(msgURL)
	if err != nil {
		t.Fatalf("EstablishC2Connection failed: %v", err)
	}
	def.CCMsgConn = conn // Set global connection for CCMsgTun

	// Start CCMsgTun
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := c2transport.MsgTunneler(handler.HandleC2Command, ctx, cancel); err != nil {
			t.Logf("CCMsgTun exited with error: %v", err)
		}
	}()

	t.Log("Successfully connected to C2 and started MsgTun")

	// Wait for agent to be registered on server
	time.Sleep(2 * time.Second)

	// Verify agent is registered
	agent := agents.GetAgentByTag(agentUUID)
	if agent == nil {
		t.Fatalf("Agent not found on server")
	}
	t.Logf("Agent found on server: %s", agent.Tag)

	// Set active agent
	live.ActiveAgent = agent

	// Send Command "ls"
	cmdID := "test-cmd-id"
	err = agents.SendCmd("ls", cmdID, agent)
	if err != nil {
		t.Fatalf("Failed to send command: %v", err)
	}
	t.Log("Successfully sent command 'ls'")

	// Wait for execution (logs will show output)
	time.Sleep(2 * time.Second)

	// Clean up
	cancel()
	conn.Close()
	wg.Wait()
}

func TestURLConstruction(t *testing.T) {
	// Simulated CC addresses
	ccAddresses := []string{
		"https://10.3.0.106:42933",
		"https://10.3.0.106:42933/",
	}

	token := "test-token"

	for _, ccAddr := range ccAddresses {
		// This is what failed in agent.go
		msgURL := netutil.JoinURL(ccAddr, transport.MsgAPI, token)
		expected := "https://10.3.0.106:42933/api/msg/" + token
		if msgURL != expected {
			t.Errorf("For CCAddress %q, got msgURL %q, want %q", ccAddr, msgURL, expected)
		}

		// This is what failed in reportStatus
		reportURL := netutil.JoinURL(ccAddr, transport.CheckInAPI, "some-uuid")
		expectedReport := "https://10.3.0.106:42933/api/checkin/some-uuid"
		if reportURL != expectedReport {
			t.Errorf("For CCAddress %q, got reportURL %q, want %q", ccAddr, reportURL, expectedReport)
		}
	}
}

func TestHandshakePrefixMismatch(t *testing.T) {
	// Setup temp dir for certs
	tmpDir, err := os.MkdirTemp("", "agent_test_mismatch")
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

	// Save original prefix
	origPrefix := def.TransportString
	defer func() { def.TransportString = origPrefix }()

	// Server prefix
	def.TransportString = "server-prefix"

	// Setup C2 Config
	live.RuntimeConfig = &def.Config{
		CCPort: fmt.Sprintf("%d", port),
		CAPEM:  string(caCertData),
	}

	// Start Real C2 Server
	go server.StartC2AgentTLSServer()

	// Wait for server to start
	time.Sleep(5 * time.Second)

	// Setup Agent Config
	agentUUID := "test-agent-uuid-mismatch"
	agentSig, err := signUUID(agentUUID, caKeyFile)
	if err != nil {
		t.Fatalf("Failed to sign UUID: %v", err)
	}

	c2URL := fmt.Sprintf("https://127.0.0.1:%d", port)
	common.RuntimeConfig = &def.Config{
		CCAddress:    c2URL,
		AgentUUID:    agentUUID,
		AgentUUIDSig: agentSig,
		AgentTag:     agentUUID,
		CCTimeout:    1000, // Short timeout for test
	}
	def.CCAddress = c2URL

	// Agent explicitly uses a different prefix
	// We need to override def.TransportString before calling MsgTunneler
	// but after the server has started (it uses the same global)
	// This is a bit tricky since they share the same memory in the test.
	// In a real scenario, they are separate processes.

	// For the sake of this test, we want to see the server's warning.
	// We will manually construct a message with the wrong prefix but valid signature.

	// Initialize HTTP Client
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCertData)
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: certPool},
		ForceAttemptHTTP2: true,
	}
	def.HTTPClient = &http.Client{Transport: tr}

	// ReportStatus (this should still work as it doesn't use the prefix)
	agentInfo := &def.Emp3r0rAgent{
		Tag:     agentUUID,
		Name:    "test-agent",
		UUID:    agentUUID,
		UUIDSig: agentSig,
	}
	c2transport.ReportStatus(agentInfo)

	// Connect to MsgAPI
	msgURL := fmt.Sprintf("%s/%s/%s", c2URL, transport.MsgAPI, "test-token")
	conn, _, cancel, err := c2transport.EstablishC2Connection(msgURL)
	if err != nil {
		t.Fatalf("EstablishC2Connection failed: %v", err)
	}
	defer conn.Close()
	defer cancel()

	// Now, manually send a message with a mismatched prefix
	// The server's TransportString is currently "server-prefix"
	mismatchedMsg := def.MsgTunData{
		CmdSlice: []string{"mismatched-prefix", agentUUID, agentSig, "extra"},
		CmdID:    uuid.NewString(),
		Tag:      agentUUID,
	}
	encoder := cbor.NewEncoder(conn)
	if err := encoder.Encode(mismatchedMsg); err != nil {
		t.Fatalf("Failed to send mismatched message: %v", err)
	}

	// Wait for a bit for the server to process it
	time.Sleep(1 * time.Second)

	t.Log("Test finished, check logs for 'prefix mismatch' warning")
}
