package c2transport_test

// tun2socks_pivot_test.go — drive the real CC SOCKS5 pivot
// (server.StartSocks5Proxy / internal/cc/server/socks5.go) the same way the
// tun2socks engine does: with sing's socks5 client (the exact client the
// pivotHandler uses), and also through the actual TUN device routing a real
// destination (1.1.1.1).
//
// Test 1 (interop, no TUN): sing socks5 client -> real CC pivot -> agent ->
// loopback echo. Proves tun2socks's SOCKS client speaks the pivot's dialect.
//
// Test 2 (TUN routing, single host): route 1.1.1.1 through the TUN and dial
// it. The agent runs on the same host as the TUN, so its own dial to 1.1.1.1
// is captured by the TUN again -> feedback loop. This is the co-located-agent
// topology; a remote agent does not re-enter the operator's TUN.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
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
	tun2socks "github.com/jm33-m0/emp3r0r/core/internal/cc/base/tun2socks"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/server"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

// startPivotStack stands up a real C2 server + one real agent + the real
// SOCKS5 pivot, and returns the pivot address plus a cleanup func.
func startPivotStack(t *testing.T) (pivotAddr string) {
	t.Helper()
	mode := def.C2ChannelModeH2Conn

	tmpDir, err := os.MkdirTemp("", "tun2socks_pivot_test")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

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

	go server.StartC2AgentTLSServer()
	server.MarkOperatorOnline("test-operator")
	t.Cleanup(func() {
		server.MarkOperatorOffline("test-operator")
		network.StopEmpTLSServer()
	})
	time.Sleep(1 * time.Second)

	// Agent identity + enrollment + message tunnel.
	agentUUID := uuid.New().String()
	agentTag := "tun2socks-agent-" + uuid.New().String()[:8]
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

	ccBase := fmt.Sprintf("https://127.0.0.1:%d", tlsPort)
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
		Tag: agentTag, Name: "tun2socks-pivot", Version: "test", Transport: "HTTP2",
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
	t.Cleanup(func() {
		tunnelCancel()
		if tunnelConn != nil {
			_ = tunnelConn.Close()
		}
		select {
		case <-tunDone:
		case <-time.After(3 * time.Second):
		}
	})

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
	time.Sleep(500 * time.Millisecond)

	if err := server.StartSocks5Proxy(agentTag, socksPort, "127.0.0.1"); err != nil {
		t.Fatalf("StartSocks5Proxy: %v", err)
	}
	t.Cleanup(func() { _ = server.StopSocks5Proxy(socksPort) })
	t.Logf("real SOCKS5 pivot on 127.0.0.1:%d via agent %s", socksPort, agentTag)
	return fmt.Sprintf("127.0.0.1:%d", socksPort)
}

func startLoopbackEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// TestTun2SocksPivotSingClientInterop uses the exact SOCKS client the
// tun2socks engine dials with (sing socks.Client) against the real CC pivot,
// with a loopback target the co-located agent can reach directly. No TUN is
// involved, so this isolates the protocol layer.
func TestTun2SocksPivotSingClientInterop(t *testing.T) {
	pivot := startPivotStack(t)
	echo := startLoopbackEcho(t)

	client := socks.NewClient(N.SystemDialer, M.ParseSocksaddr(pivot), socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := client.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(echo))
	if err != nil {
		t.Fatalf("sing socks client CONNECT %s via real pivot: %v", echo, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	payload := []byte("tun2socks-sing-client-interop")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", buf, payload)
	}
	t.Logf("PASS: sing socks5 client <-> real CC pivot <-> agent round trip OK")
}

// TestTun2SocksPivotRoute1111 routes 1.1.1.1 through a real TUN device and
// dials it through the real CC pivot + agent. On a single host the agent's own
// dial to 1.1.1.1 is captured by the TUN again (feedback loop: the agent dial
// re-enters the TUN and the chain never bottoms out), which is what we observe
// here. Requires admin + a TUN device, and is skipped unless
// EMP3R0R_TUN_E2E=1 is set, because the loop is the expected outcome on a
// single host (a remote agent does not re-enter the operator's TUN).
func TestTun2SocksPivotRoute1111(t *testing.T) {
	if os.Getenv("EMP3R0R_TUN_E2E") == "" {
		t.Skip("set EMP3R0R_TUN_E2E=1 to run the single-host TUN routing observation")
	}
	pivot := startPivotStack(t)

	eng, err := tun2socks.Start(tun2socks.Config{
		Name:         "emp3r0r0",
		MTU:          1500,
		Inet4Address: []netip.Prefix{netip.MustParsePrefix("10.0.8.1/24")},
		Socks5Addr:   pivot,
		Route:        []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32")},
		RouteExcludes: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.1/32"),
		},
		LogTag: "e2e-1111",
	})
	if err != nil {
		t.Fatalf("tun2socks start: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close() })

	target := "1.1.1.1:80"
	t.Logf("dialing %s through the TUN", target)
	conn, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		t.Logf("as expected on a single host (agent dial re-enters the TUN): %v", err)
		return // not a hard failure here; see comment above the test
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n")); err != nil {
		t.Logf("write failed: %v", err)
		return
	}
	resp, _ := io.ReadAll(io.LimitReader(conn, 512))
	t.Logf("HTTP response (%d bytes)", len(resp))
}
