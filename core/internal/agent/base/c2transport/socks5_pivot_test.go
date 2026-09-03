package c2transport_test

// socks5_pivot_test.go — end-to-end SOCKS5 pivot over the C2 channel.
//
// Topology under test (Cobalt Strike style, stream based):
//
//	proxychains-style socks5 client
//	         │  CONNECT <target>
//	         ▼
//	CC-side SOCKS5 listener (server.StartSocks5Proxy)
//	         │  orders agent over the CBOR msg tunnel: !proxy_start
//	         ▼
//	agent opens a dedicated C2 stream on the Proxy route (PFS session key)
//	         │
//	         ▼
//	agent dials <target> and relays
//
// We assert: socks5 negotiation, CONNECT ack ordering, and byte round trips
// between the operator-side client and a local echo server behind the agent,
// for both C2 channel wrappers (h2conn and http_poll).

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/handler"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/server"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func TestSocks5PivotEndToEnd(t *testing.T) {
	for _, mode := range []string{def.C2ChannelModeH2Conn, def.C2ChannelModePlainHTTP} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			runSocks5PivotE2E(t, mode, false)
		})
	}
}

func TestSocks5PivotCONNECTRefused(t *testing.T) {
	for _, mode := range []string{def.C2ChannelModeH2Conn, def.C2ChannelModePlainHTTP} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			runSocks5PivotE2E(t, mode, true)
		})
	}
}

// runSocks5PivotE2E stands up a real C2 server + real agent and drives a raw
// SOCKS5 client through the pivot. When expectRefused is true the target port
// is closed and the CONNECT must come back with a failure reply.
func runSocks5PivotE2E(t *testing.T, mode string, expectRefused bool) {
	t.Helper()

	// -----------------------------------------------------------------------
	// Certs + runtime config (mirrors plain_http_test / lifecycle_test setup).
	// -----------------------------------------------------------------------
	tmpDir, err := os.MkdirTemp("", "socks5_pivot_test")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	caCertFile := filepath.Join(tmpDir, "ca-cert.pem")
	caKeyFile := filepath.Join(tmpDir, "ca-key.pem")
	serverCertFile := filepath.Join(tmpDir, "server-cert.pem")
	serverKeyFile := filepath.Join(tmpDir, "server-key.pem")
	if _, err = transport.GenCerts(nil, caCertFile, caKeyFile, "", "", true); err != nil {
		t.Fatalf("GenCerts CA: %v", err)
	}
	if _, err = transport.GenCerts([]string{"127.0.0.1"}, serverCertFile, serverKeyFile, caKeyFile, caCertFile, false); err != nil {
		t.Fatalf("GenCerts server: %v", err)
	}
	caCertData, err := os.ReadFile(caCertFile)
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	transport.CACrtPEM = caCertData
	transport.CaCrtFile = caCertFile
	transport.CaKeyFile = caKeyFile
	transport.OperatorCaCrtFile = caCertFile
	transport.ServerCrtFile = serverCertFile
	transport.ServerKeyFile = serverKeyFile
	transport.EmpWorkSpace = tmpDir
	live.EmpWorkSpace = tmpDir

	freePort := func() int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("free port: %v", err)
		}
		p := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		return p
	}
	tlsPort := freePort()
	httpPort := freePort()
	socksPort := freePort()
	deadPort := freePort() // used when expectRefused: nothing listens here

	routes := def.C2Routing{
		Checkin: "c2-checkin",
		Msg:     "c2-msg",
		FTP:     "c2-ftp",
		WWW:     "c2-www",
		Proxy:   "c2-proxy",
	}
	malleable := def.MalleableHTTPConfig{
		C2Path:        "/api/v1/telemetry",
		SessionHeader: "Cookie",
		SessionValue:  "sessionID=%s",
		InitHeader:    "Cookie",
		InitValue:     "init=1",
		CloseHeader:   "Cookie",
		CloseValue:    "close=1",
	}

	live.AgentControlMap = sync.Map{}
	live.AgentList = sync.Map{}
	live.RuntimeConfig = &def.Config{
		CCH2Port:      fmt.Sprintf("%d", tlsPort),
		CCHTTPPort:    fmt.Sprintf("%d", httpPort),
		CAPEM:         string(caCertData),
		C2ChannelMode: mode,
		C2Routes:      routes,
		MalleableC2:   malleable,
	}

	// Real C2 servers.
	go server.StartC2AgentTLSServer()
	server.MarkOperatorOnline("test-operator")
	t.Cleanup(func() {
		server.MarkOperatorOffline("test-operator")
		network.StopEmpTLSServer()
	})
	if mode == def.C2ChannelModePlainHTTP {
		go server.StartC2HTTPServer()
	}
	time.Sleep(1 * time.Second)

	// -----------------------------------------------------------------------
	// Agent identity + enrollment + message tunnel (PFS handshake inside).
	// -----------------------------------------------------------------------
	agentUUID := uuid.New().String()
	agentTag := "socks5-agent-" + uuid.New().String()[:8]
	agentPriv, agentPub, err := genAgentKey()
	if err != nil {
		t.Fatalf("genAgentKey: %v", err)
	}
	agentutils.AgentKey = agentPriv
	caKey, err := transport.ParseKeyPemFile(caKeyFile)
	if err != nil {
		t.Fatalf("parse CA key: %v", err)
	}
	agentSig, err := signUUID(agentUUID, caKey)
	if err != nil {
		t.Fatalf("signUUID: %v", err)
	}

	var ccBase string
	if mode == def.C2ChannelModePlainHTTP {
		ccBase = fmt.Sprintf("http://127.0.0.1:%d", httpPort)
	} else {
		ccBase = fmt.Sprintf("https://127.0.0.1:%d", tlsPort)
	}
	common.RuntimeConfig = &def.Config{
		CCAddress:     ccBase,
		CCH2Port:      fmt.Sprintf("%d", tlsPort),
		CCHTTPPort:    fmt.Sprintf("%d", httpPort),
		C2ChannelMode: mode,
		CAPEM:         string(caCertData),
		C2Routes:      routes,
		MalleableC2:   malleable,
		AgentUUID:     agentUUID,
		AgentUUIDSig:  agentSig,
		AgentTag:      agentTag,
		CCTimeout:     10000,
	}
	def.CCAddress = ccBase
	def.HTTPClient = transport.CreateEmp3r0rHTTPClient(def.CCAddress, "")
	if def.HTTPClient == nil {
		t.Fatalf("CreateEmp3r0rHTTPClient failed")
	}

	if err = c2transport.ReportStatus(common.RuntimeConfig, &def.Emp3r0rAgent{
		Tag: agentTag, Name: "socks5-pivot", Version: "test", Transport: "HTTP2",
		OS: "Linux", GOOS: "linux", IPs: []string{"127.0.0.1"},
		Process: &def.AgentProcess{}, UUID: agentUUID, UUIDSig: agentSig, PublicKey: agentPub,
	}); err != nil {
		t.Fatalf("ReportStatus: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	tunnelConn, tunnelCtx, tunnelCancel, err := c2transport.EstablishC2Connection(ccBase, "", common.RuntimeConfig.C2Routes.Msg)
	if err != nil {
		t.Fatalf("EstablishC2Connection(msg): %v", err)
	}
	def.CCMsgConn = tunnelConn
	tunDone := make(chan struct{})
	go func() {
		defer close(tunDone)
		_ = c2transport.MsgTunneler(tunnelConn, common.RuntimeConfig, handler.HandleC2Command, tunnelCtx, tunnelCancel)
	}()
	defer func() {
		tunnelCancel()
		if tunnelConn != nil {
			_ = tunnelConn.Close()
		}
		select {
		case <-tunDone:
		case <-time.After(3 * time.Second):
		}
	}()

	deadline := time.Now().Add(20 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("agent never reached live tunnel state")
		}
		admitted := false
		live.AgentControlMap.Range(func(key, value any) bool {
			k := key.(*def.Emp3r0rAgent)
			v := value.(*live.AgentControl)
			if k.Tag == agentTag && v.Conn != nil {
				admitted = true
				return false
			}
			return true
		})
		if admitted {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond) // let the PFS exchange settle

	// -----------------------------------------------------------------------
	// Local echo target "behind" the agent.
	// -----------------------------------------------------------------------
	var targetPort int
	if expectRefused {
		targetPort = deadPort
	} else {
		echoLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("echo listen: %v", err)
		}
		defer echoLn.Close()
		targetPort = echoLn.Addr().(*net.TCPAddr).Port
		go func() {
			for {
				conn, err := echoLn.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					_, _ = io.Copy(conn, conn)
				}()
			}
		}()
	}

	// -----------------------------------------------------------------------
	// CC-side SOCKS5 pivot bound to the agent.
	// -----------------------------------------------------------------------
	if err := server.StartSocks5Proxy(agentTag, socksPort, "127.0.0.1"); err != nil {
		t.Fatalf("StartSocks5Proxy: %v", err)
	}
	defer server.StopSocks5Proxy(socksPort)

	// -----------------------------------------------------------------------
	// Proxychains-style client.
	// -----------------------------------------------------------------------
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 5*time.Second)
	if err != nil {
		t.Fatalf("dial socks5 listener: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(40 * time.Second))

	if _, err = conn.Write([]byte{0x05, 0x01, 0x00}); err != nil { // v5, no auth
		t.Fatalf("write greeting: %v", err)
	}
	greetReply := make([]byte, 2)
	if _, err = io.ReadFull(conn, greetReply); err != nil {
		t.Fatalf("read greeting reply: %v", err)
	}
	if greetReply[0] != 0x05 || greetReply[1] != 0x00 {
		t.Fatalf("unexpected greeting reply: %v", greetReply)
	}

	// CONNECT 127.0.0.1:<targetPort>
	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1}
	req = append(req, byte(targetPort>>8), byte(targetPort&0xff))
	if _, err = conn.Write(req); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	connectReply := make([]byte, 10)
	if _, err = io.ReadFull(conn, connectReply); err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}
	if expectRefused {
		if connectReply[1] == 0x00 {
			t.Fatalf("expected failure reply for unreachable target, got success")
		}
		logging.Successf("CONNECT refused as expected (rep=0x%02x)", connectReply[1])
		return
	}
	if connectReply[1] != 0x00 {
		t.Fatalf("CONNECT failed with rep 0x%02x", connectReply[1])
	}

	// Byte round trips through the whole pivot.
	payload := []byte("socks5-pivot-echo-1234567890")
	for i := 0; i < 3; i++ {
		if _, err = conn.Write(payload); err != nil {
			t.Fatalf("write payload: %v", err)
		}
		buf := make([]byte, len(payload))
		if _, err = io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read echoed payload: %v", err)
		}
		if string(buf) != string(payload) {
			t.Fatalf("echo mismatch: got %q want %q", buf, payload)
		}
	}
	logging.Successf("SOCKS5 pivot round trip OK (%d bytes x3)", len(payload))
}
