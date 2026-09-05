package c2transport_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/netutil"
)

func genAgentKey() (*ecdsa.PrivateKey, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	pubBytes, err := transport.PublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		return nil, "", err
	}
	return priv, string(pubBytes), nil
}

func signUUID(uuid string, privKey *ecdsa.PrivateKey) (string, error) {
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

func startTestC2Server(t *testing.T) {
	t.Helper()
	go server.StartC2AgentTLSServer()
	server.MarkOperatorOnline("test-operator")
	t.Cleanup(func() {
		server.MarkOperatorOffline("test-operator")
		network.StopEmpTLSServer()
		_ = agents.CloseAgentDB()
		// Allow in-flight stream handlers to observe shutdown and exit.
		time.Sleep(150 * time.Millisecond)
	})
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
	transport.CaKeyFile = caKeyFile
	transport.OperatorCaCrtFile = caCertFile // Set OperatorCaCrtFile for apiDispatcher
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
	startTestC2Server(t)

	// Wait for server to start
	time.Sleep(2 * time.Second)

	// Setup Agent Config
	agentUUID := "test-agent-uuid"

	// Gen Agent Key (TOFU)
	agentPriv, agentPub, err := genAgentKey()
	if err != nil {
		t.Fatalf("Failed to gen agent key: %v", err)
	}
	// SET GLOBAL AGENT KEY for MsgTunneler signing
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
		AgentTag:      agentUUID, // Set AgentTag to match UUID for test
		CCTimeout:     10000,     // Set timeout to 10 seconds
		C2Routes:      live.RuntimeConfig.C2Routes,
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
		PublicKey: agentPub,
	}
	config := common.RuntimeConfig
	err = c2transport.ReportStatus(config, agentInfo)
	if err != nil {
		t.Fatalf("ReportStatus failed: %v", err)
	}
	t.Log("Successfully checked in")

	// Allow time for agent to be fully registered
	time.Sleep(100 * time.Millisecond)

	// Construct MsgAPI URL
	msgURL := fmt.Sprintf("%s/%s/%s", c2URL, transport.MsgAPI, "test-token")

	// Test EstablishC2Connection
	conn, ctx, cancel, err := c2transport.EstablishC2Connection(msgURL, "", common.RuntimeConfig.C2Routes.Msg)
	if err != nil {
		t.Fatalf("EstablishC2Connection failed: %v", err)
	}
	def.CCMsgConn = conn // Set global connection for CCMsgTun

	// Start CCMsgTun
	tunDone := make(chan struct{})
	go func() {
		defer close(tunDone)
		if err := c2transport.MsgTunneler(conn, config, handler.HandleC2Command, ctx, cancel); err != nil {
			// Use logging.Printf instead of t.Logf since goroutine may outlive test
			// This prevents "Log in goroutine after test has completed" panic
			if !strings.Contains(err.Error(), "context canceled") && !strings.Contains(err.Error(), "closed") {
				logging.Errorf("CCMsgTun exited with error: %v", err)
			}
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
	go conn.Close()
	// Clean up
	cancel()
	go conn.Close()
	select {
	case <-tunDone:
	case <-time.After(1 * time.Second):
		t.Log("MsgTunneler did not exit in time (pending I/O), forcing test completion")
	}
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

func TestDuplicatedCheckin(t *testing.T) {
	// Setup temp dir for certs
	tmpDir, err := os.MkdirTemp("", "agent_test_dupe")
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

	// Reset live maps without replacing sync.Map instance (avoids races with goroutines)
	live.AgentControlMap.Range(func(key, _ any) bool {
		live.AgentControlMap.Delete(key)
		return true
	})
	// Clear AgentList in place to match AgentControlMap above.
	live.AgentList.Clear()

	// Start Real C2 Server
	startTestC2Server(t)

	// Wait for server to start
	time.Sleep(3 * time.Second)

	// Setup Agent Config
	agentUUID := "dupe-agent-uuid"
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
		AgentTag:      agentUUID,
		CCTimeout:     3000,
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

	// First agent check-in
	agentInfo := &def.Emp3r0rAgent{
		Tag:       agentUUID,
		Name:      "test-agent",
		UUID:      agentUUID,
		UUIDSig:   agentSig,
		PublicKey: agentPub,
	}
	config := common.RuntimeConfig
	err = c2transport.ReportStatus(config, agentInfo)
	if err != nil {
		t.Fatalf("First ReportStatus failed: %v", err)
	}

	// Allow time for agent to be fully registered
	time.Sleep(100 * time.Millisecond)

	// Establish persistent connection for first agent
	msgURL := fmt.Sprintf("%s/%s/%s", c2URL, transport.MsgAPI, "test-token")
	conn, ctx, cancel, err := c2transport.EstablishC2Connection(msgURL, "", common.RuntimeConfig.C2Routes.Msg)
	if err != nil {
		t.Fatalf("EstablishC2Connection failed: %v", err)
	}
	def.CCMsgConn = conn
	defer conn.Close()
	defer cancel()

	// Start MsgTun for the first agent
	tunDone := make(chan struct{})
	go func() {
		defer close(tunDone)
		// Ignore errors since goroutine may outlive test
		_ = c2transport.MsgTunneler(conn, config, func(data *def.MsgTunData) {}, ctx, cancel)
	}()

	// Wait for CC to process the connection
	time.Sleep(2 * time.Second)

	// Second agent (same Tag) attempts to check in
	configDupe := common.RuntimeConfig
	err = c2transport.ReportStatus(configDupe, agentInfo)

	if err != nil {
		t.Logf("Second ReportStatus failed early as expected: %v", err)
		if !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "reset") && !strings.Contains(err.Error(), "forbidden") {
			t.Errorf("Unexpected error from second ReportStatus: %v", err)
		}
	} else {
		t.Log("Second ReportStatus returned nil (async write). The server will drop the connection.")
	}

	// Cleanup
	cancel()
	go conn.Close() // Close connection asynchronously to unblock MsgTunneler reads
	// Cleanup
	cancel()
	go conn.Close() // Close connection asynchronously to unblock MsgTunneler reads
	select {
	case <-tunDone:
	case <-time.After(1 * time.Second):
		t.Log("MsgTunneler did not exit in time (pending I/O), forcing test completion")
	}
}

func TestBackslashTag(t *testing.T) {
	// Setup temp dir for certs
	tmpDir, err := os.MkdirTemp("", "agent_test_backslash")
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
	startTestC2Server(t)

	// Wait for server to start
	time.Sleep(2 * time.Second)

	// Setup Agent Config with Safe UUID but Backslash Tag
	agentUUID := uuid.New().String()
	agentTag := "kali\\kali_0-agent-custom"
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
		Name:      "test-agent-backslash",
		UUID:      agentUUID,
		UUIDSig:   agentSig,
		PublicKey: agentPub,
	}
	config := common.RuntimeConfig
	err = c2transport.ReportStatus(config, agentInfo)
	if err != nil {
		t.Fatalf("ReportStatus failed with backslash tag: %v", err)
	}
	t.Log("Successfully checked in with backslash tag")

	// Allow time for agent to be fully registered
	time.Sleep(100 * time.Millisecond)
}

func TestEmptyUUID(t *testing.T) {
	// Setup temp dir for certs
	tmpDir, err := os.MkdirTemp("", "agent_test_empty")
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
	startTestC2Server(t)

	// Wait for server to start
	time.Sleep(2 * time.Second)

	// Setup Agent Config with EMPTY UUID
	agentUUID := ""
	agentTag := "kali-agent-fallback"
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
		Name:      "test-agent-empty",
		UUID:      agentUUID,
		UUIDSig:   agentSig,
		PublicKey: agentPub,
	}
	config := common.RuntimeConfig
	err = c2transport.ReportStatus(config, agentInfo)
	if err == nil {
		t.Fatalf("ReportStatus matched with empty UUID??")
	}
	t.Logf("ReportStatus failed as expected: %v", err)
	if !strings.Contains(err.Error(), "missing agent UUID") {
		t.Errorf("Expected missing agent UUID error, got: %v", err)
	}
}

func TestNewAgentCheckin(t *testing.T) {
	// Setup temp dir for certs
	tmpDir, err := os.MkdirTemp("", "agent_test_new")
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
	startTestC2Server(t)

	// Wait for server to start
	time.Sleep(2 * time.Second)

	// Setup Agent Config with VALID NEW UUID
	agentUUID := uuid.New().String()
	agentTag := "new-agent-tag"
	// Gen Agent Key (TOFU)
	agentPriv, agentPub, err := genAgentKey()
	if err != nil {
		t.Fatalf("Failed to gen agent key: %v", err)
	}
	agentutils.AgentKey = agentPriv
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
		Name:      "test-new-agent",
		UUID:      agentUUID,
		UUIDSig:   agentSig,
		PublicKey: agentPub,
	}
	config := common.RuntimeConfig
	err = c2transport.ReportStatus(config, agentInfo)
	if err != nil {
		t.Fatalf("ReportStatus failed for new agent: %v", err)
	}
	t.Log("Successfully checked in new agent")

	// Allow time for agent to be fully registered
	time.Sleep(100 * time.Millisecond)
}
