package c2transport_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/paths"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/server"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

func waitForPort(addr string, deadline time.Time) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for %s to accept connections", addr)
		}
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		<-ticker.C
	}
}

// waitForTLSPort waits until a TLS listener completes a handshake. Testing with
// a plain TCP dial produces spurious "TLS handshake error: EOF" logs and can
// report ready before the certificate/HTTP2 stack is actually serving.
func waitForTLSPort(addr string, deadline time.Time) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	dialer := &net.Dialer{Timeout: 500 * time.Millisecond}
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for TLS listener %s", addr)
		}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true}) // test-only readiness probe
		if err == nil {
			_ = conn.Close()
			return nil
		}
		<-ticker.C
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("reserve UDP port: %v", err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func runCheckinACK(t *testing.T, mode string, quicStandardKey, httpPollOverTLS bool) {
	t.Helper()
	transport.SetQUICStandardKey(quicStandardKey)
	t.Cleanup(func() { transport.SetQUICStandardKey(false) })

	// The package shares process-wide agent/C2 state. Snapshot every global this
	// test mutates and restore it only after the server goroutine has stopped;
	// otherwise a slow handler from this test can race the next test's setup.
	origLiveRuntime := live.GetRuntimeConfig()
	origEmpWorkSpace := live.EmpWorkSpace
	origWWWRoot := paths.WWWRoot
	origCCAddr := def.CCAddress
	origHTTPClient := def.HTTPClient
	origCommonRuntime := common.RuntimeConfig
	origAgentKey := agentutils.AgentKey
	origCACrtPEM := transport.GetCACrtPEM()
	origCaCrtFile := transport.CaCrtFile
	origCaKeyFile := transport.CaKeyFile
	origServerCrtFile := transport.ServerCrtFile
	origServerKeyFile := transport.ServerKeyFile
	origTransportWorkSpace := transport.EmpWorkSpace
	t.Cleanup(func() {
		live.SetRuntimeConfig(origLiveRuntime)
		live.EmpWorkSpace = origEmpWorkSpace
		paths.WWWRoot = origWWWRoot
		def.CCAddress = origCCAddr
		def.HTTPClient = origHTTPClient
		common.RuntimeConfig = origCommonRuntime
		agentutils.AgentKey = origAgentKey
		transport.SetCACrtPEM(origCACrtPEM)
		transport.CaCrtFile = origCaCrtFile
		transport.CaKeyFile = origCaKeyFile
		transport.ServerCrtFile = origServerCrtFile
		transport.ServerKeyFile = origServerKeyFile
		transport.EmpWorkSpace = origTransportWorkSpace
	})

	// Stop any endpoint left by an earlier test before initializing the DB.
	network.StopEmpServers()
	if agents.AgentDB != nil {
		_ = agents.CloseAgentDB()
	}

	tmpDir := t.TempDir()
	caCertFile := filepath.Join(tmpDir, "ca-cert.pem")
	caKeyFile := filepath.Join(tmpDir, "ca-key.pem")
	serverCertFile := filepath.Join(tmpDir, "server-cert.pem")
	serverKeyFile := filepath.Join(tmpDir, "server-key.pem")

	if _, err := transport.GenCerts(nil, caCertFile, caKeyFile, "", "", true); err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}
	if _, err := transport.GenCerts([]string{"127.0.0.1"}, serverCertFile, serverKeyFile, caKeyFile, caCertFile, false); err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	caCertData, err := os.ReadFile(caCertFile)
	if err != nil {
		t.Fatalf("Failed to read CA cert: %v", err)
	}
	transport.SetCACrtPEM(caCertData)
	transport.CaCrtFile = caCertFile
	transport.CaKeyFile = caKeyFile
	transport.ServerCrtFile = serverCertFile
	transport.ServerKeyFile = serverKeyFile
	transport.EmpWorkSpace = tmpDir
	live.EmpWorkSpace = tmpDir
	paths.WWWRoot = filepath.Join(tmpDir, "www")
	if err := os.MkdirAll(paths.WWWRoot, 0o700); err != nil {
		t.Fatalf("create WWW root: %v", err)
	}

	tlsPort := freeTCPPort(t)
	if mode == def.C2ChannelModeQUIC {
		// QUIC needs a free UDP port; a TCP reservation says nothing about UDP
		// and made the QUIC subtests intermittently collide with another socket.
		tlsPort = freeUDPPort(t)
	}
	httpPort := freeTCPPort(t)

	live.SetRuntimeConfig(&def.Config{
		CCH2Port:        fmt.Sprintf("%d", tlsPort),
		CCHTTPPort:      fmt.Sprintf("%d", httpPort),
		CAPEM:           string(caCertData),
		C2ChannelMode:   mode,
		QUICStandardKey: quicStandardKey,
		C2Routes: def.C2Routing{
			Checkin: "c2-checkin",
			Msg:     "c2-msg",
			FTP:     "c2-ftp",
			WWW:     "c2-www",
			Proxy:   "c2-proxy",
		},
		MalleableC2: def.MalleableHTTPConfig{
			C2Path:        "/api/v1/telemetry",
			SessionHeader: "Cookie",
			SessionValue:  "sessionID=%s",
			InitHeader:    "Cookie",
			InitValue:     "init=1",
			CloseHeader:   "Cookie",
			CloseValue:    "close=1",
		},
	})
	live.ClearAgents()

	// Initialize the trust store before any listener accepts a request. The
	// server used to do this lazily on its startup goroutine, so a fast first
	// check-in could race ahead of table creation and be rejected with EOF.
	// The DB is also why the old test started the TLS server even for http_poll;
	// initialize it explicitly and start only the transport under test.
	if err := agents.InitAgentDB(filepath.Join(tmpDir, "agents.db")); err != nil {
		t.Fatalf("InitAgentDB: %v", err)
	}
	t.Cleanup(func() {
		_ = agents.CloseAgentDB()
		live.ClearAgents()
	})

	// The dispatcher rejects an unknown agent when no operator is online; this
	// test only needs the check-in path, so register a placeholder and remove it
	// in cleanup instead of leaking operator state.
	const testOperator = "c2transport-checkin-test"
	server.MarkOperatorOnline(testOperator)
	t.Cleanup(func() { server.MarkOperatorOffline(testOperator) })

	serverDone := make(chan struct{})
	startErr := make(chan error, 1)
	go func() {
		defer close(serverDone)
		switch {
		case mode == def.C2ChannelModePlainHTTP && !httpPollOverTLS:
			server.StartC2HTTPServer()
		case mode == def.C2ChannelModePlainHTTP && httpPollOverTLS:
			_ = server.StartC2TLSStreamServer()
		case mode == def.C2ChannelModeQUIC:
			startErr <- server.StartC2AgentTLSServer()
		default:
			_ = server.StartC2AgentTLSServer()
		}
	}()
	t.Cleanup(func() {
		network.StopEmpServers()
		select {
		case <-serverDone:
		case <-time.After(5 * time.Second):
			t.Errorf("C2 %s server did not stop within 5s", mode)
		}
	})

	switch {
	case mode == def.C2ChannelModePlainHTTP && !httpPollOverTLS:
		if err := waitForPort(fmt.Sprintf("127.0.0.1:%d", httpPort), time.Now().Add(10*time.Second)); err != nil {
			t.Fatalf("Plain HTTP server did not become ready: %v", err)
		}
	case mode == def.C2ChannelModeQUIC:
		// StartC2AgentTLSServer returns after the QUIC listener is bound; no
		// bind-probing loop is needed (and probing was itself racy).
		select {
		case err := <-startErr:
			if err != nil {
				t.Fatalf("QUIC C2 server did not start: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("QUIC C2 server did not start within 10s")
		}
	default:
		if err := waitForTLSPort(fmt.Sprintf("127.0.0.1:%d", tlsPort), time.Now().Add(10*time.Second)); err != nil {
			t.Fatalf("TLS C2 server did not become ready: %v", err)
		}
	}

	agentUUID := uuid.NewString()
	agentPriv, agentPub, err := genAgentKey()
	if err != nil {
		t.Fatalf("Failed to generate agent key: %v", err)
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

	common.RuntimeConfig = &def.Config{
		CCAddress:       "127.0.0.1",
		CCH2Port:        fmt.Sprintf("%d", tlsPort),
		CCHTTPPort:      fmt.Sprintf("%d", httpPort),
		C2ChannelMode:   mode,
		QUICStandardKey: quicStandardKey,
		CAPEM:           string(caCertData),
		C2Routes:        live.GetRuntimeConfig().C2Routes,
		AgentUUID:       agentUUID,
		AgentUUIDSig:    sigBytes(t, agentSig),
		AgentTag:        agentUUID,
		MalleableC2:     live.GetRuntimeConfig().MalleableC2,
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(caCertData); !ok {
		t.Fatalf("Failed to append CA cert")
	}

	if mode == def.C2ChannelModePlainHTTP {
		if httpPollOverTLS {
			def.CCAddress = fmt.Sprintf("https://127.0.0.1:%d", tlsPort)
		} else {
			def.CCAddress = fmt.Sprintf("http://127.0.0.1:%d", httpPort)
		}
		def.HTTPClient = &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{RootCAs: certPool},
				ForceAttemptHTTP2: true,
			},
		}
	} else {
		def.CCAddress = fmt.Sprintf("https://127.0.0.1:%d", tlsPort)
		def.HTTPClient = &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{RootCAs: certPool, NextProtos: []string{"h2"}},
				ForceAttemptHTTP2: true,
			},
		}
	}

	agentInfo := &def.Emp3r0rAgent{
		Tag:       agentUUID,
		UUID:      agentUUID,
		UUIDSig:   agentSig,
		PublicKey: agentPub,
		OS:        "Linux",
		GOOS:      "linux",
		IPs:       []string{"127.0.0.1"},
		Process:   &def.AgentProcess{},
	}

	if err := c2transport.ReportStatus(common.RuntimeConfig, agentInfo); err != nil {
		t.Fatalf("ReportStatus failed for mode %s: %v", mode, err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if agents.GetAgentByUUID(agentUUID) != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Agent was not registered after %s check-in", mode)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestPlainHTTPCheckinACK(t *testing.T) {
	for _, mode := range []string{def.C2ChannelModeH2Conn, "http_poll"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			requireH2Conn(t, mode)
			runCheckinACK(t, mode, false, false)
		})
	}
}

func TestHTTPPollOverTLSFrontend(t *testing.T) {
	runCheckinACK(t, def.C2ChannelModePlainHTTP, false, true)
}

// requireH2Conn skips a subtest when it targets the h2conn channel but the
// build excluded that channel (no `with_h2conn` tag).
func requireH2Conn(t *testing.T, mode string) {
	t.Helper()
	if mode != def.C2ChannelModeH2Conn {
		return
	}
	if _, err := transport.GetC2ChannelWrapper(def.C2ChannelModeH2Conn); err != nil {
		t.Skipf("h2conn channel not compiled into this build: %v", err)
	}
}
