package tor_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/paths"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/server"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/pkg/transportbridge"

	_ "github.com/jm33-m0/emp3r0r/core/transports/tor"
)

// TestTorCustomTransportCheckin exercises the whole custom path: the Tor reference
// dialer connects through a local SOCKS5 proxy to a TCP bridge, the bridge
// forwards to the C2 Unix socket with the custom preface, and the existing C2
// dispatcher accepts the agent's first check-in.
func TestTorCustomTransportCheckin(t *testing.T) {
	origRuntime := live.GetRuntimeConfig()
	origWorkSpace := live.EmpWorkSpace
	origCommon := common.RuntimeConfig
	origCCAddress := def.CCAddress
	origHTTPClient := def.HTTPClient
	origAgentKey := agentutils.AgentKey
	origCACrtPEM := transport.GetCACrtPEM()
	origWWWRoot := paths.WWWRoot

	tmpDir := t.TempDir()
	socket := filepath.Join(tmpDir, "bridge.sock")
	routes := def.C2Routing{
		Checkin: "c2-checkin",
		Msg:     "c2-msg",
		FTP:     "c2-ftp",
		WWW:     "c2-www",
		Proxy:   "c2-proxy",
	}

	live.EmpWorkSpace = tmpDir
	live.SetRuntimeConfig(&def.Config{
		BridgeSocket:  socket,
		C2ChannelMode: "tor",
		C2Routes:      routes,
	})
	paths.WWWRoot = filepath.Join(tmpDir, "www")
	if err := os.MkdirAll(paths.WWWRoot, 0o700); err != nil {
		t.Fatalf("create WWW root: %v", err)
	}

	if err := agents.InitAgentDB(filepath.Join(tmpDir, "agents.db")); err != nil {
		t.Fatalf("InitAgentDB: %v", err)
	}
	t.Cleanup(func() {
		_ = agents.CloseAgentDB()
		live.ClearAgents()
		live.SetRuntimeConfig(origRuntime)
		live.EmpWorkSpace = origWorkSpace
		common.RuntimeConfig = origCommon
		def.CCAddress = origCCAddress
		def.HTTPClient = origHTTPClient
		agentutils.AgentKey = origAgentKey
		transport.SetCACrtPEM(origCACrtPEM)
		paths.WWWRoot = origWWWRoot
	})

	const testOperator = "tor-bridge-checkin-test"
	server.MarkOperatorOnline(testOperator)
	t.Cleanup(func() { server.MarkOperatorOffline(testOperator) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bridgeDone := make(chan error, 1)
	go func() { bridgeDone <- server.StartC2BridgeListener(ctx) }()
	waitForUnixSocket(t, socket)

	bridgeListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen bridge TCP: %v", err)
	}
	defer bridgeListener.Close()
	relayDone := make(chan error, 1)
	go func() {
		relayDone <- transportbridge.Serve(ctx, bridgeListener, transportbridge.Config{
			Transport: "tor",
			C2Socket:  socket,
		})
	}()

	socksAddr := startTestSOCKSTo(t, bridgeListener.Addr().String())

	caCertFile := filepath.Join(tmpDir, "ca-cert.pem")
	caKeyFile := filepath.Join(tmpDir, "ca-key.pem")
	if _, err := transport.GenCerts(nil, caCertFile, caKeyFile, "", "", true); err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	caPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	transport.SetCACrtPEM(caPEM)

	agentUUID := uuid.NewString()
	agentPriv, agentPub, err := genAgentKey()
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	agentutils.AgentKey = agentPriv

	agentSigB64, err := signUUID(agentUUID, caKeyFile)
	if err != nil {
		t.Fatalf("sign UUID: %v", err)
	}
	agentSig, err := base64.URLEncoding.DecodeString(agentSigB64)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	common.RuntimeConfig = &def.Config{
		CCAddress:        "example.onion:80",
		C2ChannelMode:    "tor",
		TransportOptions: map[string]string{"socks5": socksAddr},
		C2Routes:         routes,
		AgentUUID:        agentUUID,
		AgentUUIDSig:     agentSig,
		AgentTag:         agentUUID,
	}
	def.CCAddress = common.RuntimeConfig.CCAddress
	def.HTTPClient = nil

	agentInfo := &def.Emp3r0rAgent{
		Tag:       agentUUID,
		UUID:      agentUUID,
		UUIDSig:   agentSigB64,
		PublicKey: agentPub,
		OS:        "Linux",
		GOOS:      "linux",
		IPs:       []string{"127.0.0.1"},
		Process:   &def.AgentProcess{},
	}
	if err := c2transport.ReportStatus(common.RuntimeConfig, agentInfo); err != nil {
		t.Fatalf("check-in through Tor transport: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if agents.GetAgentByUUID(agentUUID) != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent was not registered after check-in through the Tor transport")
		}
		time.Sleep(50 * time.Millisecond)
	}

	cancel()
	_ = bridgeListener.Close()
	select {
	case err := <-relayDone:
		if err != nil {
			t.Fatalf("transportbridge.Serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("transport bridge did not stop")
	}
	select {
	case err := <-bridgeDone:
		if err != nil {
			t.Fatalf("StartC2BridgeListener: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("C2 bridge listener did not stop")
	}
}

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

func waitForUnixSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("bridge socket %s was not created", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// startTestSOCKSTo runs a no-auth SOCKS5 CONNECT proxy that ignores the
// requested .onion target and forwards to fixedAddr. It lets the test exercise
// the Tor dialer without a Tor daemon.
func startTestSOCKSTo(t *testing.T, fixedAddr string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen SOCKS5: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveTestSOCKSConn(conn, fixedAddr)
		}
	}()
	return ln.Addr().String()
}

func serveTestSOCKSConn(conn net.Conn, fixedAddr string) {
	defer conn.Close()

	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil || head[0] != 5 {
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, int(head[1]))); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil || req[0] != 5 || req[1] != 1 {
		return
	}
	var addrLen int
	switch req[3] {
	case 1:
		addrLen = 4
	case 3:
		one := make([]byte, 1)
		if _, err := io.ReadFull(conn, one); err != nil {
			return
		}
		addrLen = int(one[0])
	case 4:
		addrLen = 16
	default:
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, addrLen+2)); err != nil {
		return
	}

	target, err := net.Dial("tcp", fixedAddr)
	if err != nil {
		return
	}
	defer target.Close()
	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	go func() { _, _ = io.Copy(target, conn) }()
	_, _ = io.Copy(conn, target)
}
