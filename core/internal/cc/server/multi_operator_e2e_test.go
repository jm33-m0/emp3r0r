package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
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
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/wireguard"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/config"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// operatorTransportPaths mirrors the per-install certificate layout that
// transport/config_c2.go initialises at process start, rooted at dir.
func setOperatorTransportPaths(dir string) {
	transport.EmpWorkSpace = dir
	transport.CaCrtFile = filepath.Join(dir, "ca-cert.pem")
	transport.CaKeyFile = filepath.Join(dir, "ca-key.pem")
	transport.ServerCrtFile = filepath.Join(dir, "server-cert.pem")
	transport.ServerKeyFile = filepath.Join(dir, "server-key.pem")
	transport.OperatorCaCrtFile = filepath.Join(dir, "operator-ca-cert.pem")
	transport.OperatorCaKeyFile = filepath.Join(dir, "operator-ca-key.pem")
	transport.OperatorServerCrtFile = filepath.Join(dir, "operator-server-cert.pem")
	transport.OperatorServerKeyFile = filepath.Join(dir, "operator-server-key.pem")
	transport.OperatorClientCrtFile = filepath.Join(dir, "operator-client-cert.pem")
	transport.OperatorClientKeyFile = filepath.Join(dir, "operator-client-key.pem")
}

// setupServerWorkspace builds a complete C2 workspace (agent CA, operator CA
// and client identity, C2 certificates and emp3r0r.json) in dir. It restores
// every process-global it touches when the test ends.
func setupServerWorkspace(t *testing.T, dir string) {
	t.Helper()
	origWorkSpace := live.EmpWorkSpace
	origConfigFile := live.EmpConfigFile
	origConfigTar := live.EmpConfigTar
	origIsServer := live.IsServer
	origRuntime := live.RuntimeConfig
	origTransportWorkSpace := transport.EmpWorkSpace
	origCerts := [10]string{
		transport.CaCrtFile, transport.CaKeyFile,
		transport.ServerCrtFile, transport.ServerKeyFile,
		transport.OperatorCaCrtFile, transport.OperatorCaKeyFile,
		transport.OperatorServerCrtFile, transport.OperatorServerKeyFile,
		transport.OperatorClientCrtFile, transport.OperatorClientKeyFile,
	}
	origWGServerIP, origWGOperatorIP := wireguard.WgServerIP, wireguard.WgOperatorIP
	t.Cleanup(func() {
		live.EmpWorkSpace = origWorkSpace
		live.EmpConfigFile = origConfigFile
		live.EmpConfigTar = origConfigTar
		live.IsServer = origIsServer
		live.RuntimeConfig = origRuntime
		transport.EmpWorkSpace = origTransportWorkSpace
		transport.CaCrtFile, transport.CaKeyFile = origCerts[0], origCerts[1]
		transport.ServerCrtFile, transport.ServerKeyFile = origCerts[2], origCerts[3]
		transport.OperatorCaCrtFile, transport.OperatorCaKeyFile = origCerts[4], origCerts[5]
		transport.OperatorServerCrtFile, transport.OperatorServerKeyFile = origCerts[6], origCerts[7]
		transport.OperatorClientCrtFile, transport.OperatorClientKeyFile = origCerts[8], origCerts[9]
		wireguard.WgServerIP, wireguard.WgOperatorIP = origWGServerIP, origWGOperatorIP
	})

	setOperatorTransportPaths(dir)
	live.EmpWorkSpace = dir
	live.EmpConfigFile = filepath.Join(dir, "emp3r0r.json")
	live.EmpConfigTar = filepath.Join(dir, "operator_config.tar.gz")
	live.IsServer = true
	wireguard.WgServerIP = "127.0.0.1"
	wireguard.WgOperatorIP = "127.0.0.1"
	live.RuntimeConfig = &def.Config{
		CCAddress:     "127.0.0.1",
		C2ChannelMode: def.C2ChannelModeDefault,
		C2Routes: def.C2Routing{
			Checkin: "c2-checkin",
			Msg:     "c2-msg",
			FTP:     "c2-ftp",
			WWW:     "c2-www",
			Proxy:   "c2-proxy",
		},
	}
	if err := config.InitCertsAndConfig(); err != nil {
		t.Fatalf("InitCertsAndConfig: %v", err)
	}
	if err := config.GenC2Certs("127.0.0.1"); err != nil {
		t.Fatalf("GenC2Certs: %v", err)
	}
	if err := config.SaveConfigJSON(); err != nil {
		t.Fatalf("SaveConfigJSON: %v", err)
	}
	// A secret that must never be shipped to an operator.
	if err := os.WriteFile(filepath.Join(dir, "wg_config.json"), []byte(`{"operators":[]}`), 0o600); err != nil {
		t.Fatalf("write wg_config.json: %v", err)
	}
}

// tarEntryNames returns the base names of the files inside a .tar.gz.
func tarEntryNames(t *testing.T, path string) map[string]bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open tarball: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	names := map[string]bool{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		names[filepath.Base(h.Name)] = true
	}
	return names
}

// TestOperatorConfigBundleIsComplete is the regression test for the operator
// startup bug where the bundle omitted the agent CA certificate that
// config.LoadConfig reads. It also asserts private keys never leave the C2.
func TestOperatorConfigBundleIsComplete(t *testing.T) {
	serverDir := t.TempDir()
	setupServerWorkspace(t, serverDir)

	tarball, err := BuildOperatorConfigArchive()
	if err != nil {
		t.Fatalf("BuildOperatorConfigArchive: %v", err)
	}

	entries := tarEntryNames(t, tarball)
	for _, want := range operatorConfigFileNames() {
		if !entries[want] {
			t.Errorf("operator bundle is missing %s", want)
		}
	}
	for _, secret := range []string{
		"ca-key.pem",
		"server-key.pem",
		"operator-ca-key.pem",
		"operator-server-key.pem",
		"wg_config.json",
	} {
		if entries[secret] {
			t.Errorf("operator bundle leaked secret %s", secret)
		}
	}

	// A fresh operator must be able to start from exactly what the C2 shipped.
	operatorDir := t.TempDir()
	setOperatorTransportPaths(operatorDir)
	live.EmpWorkSpace = operatorDir
	live.EmpConfigFile = filepath.Join(operatorDir, "emp3r0r.json")
	live.IsServer = false
	if err := util.Unarchive(tarball, operatorDir); err != nil {
		t.Fatalf("extract operator bundle: %v", err)
	}
	if err := config.LoadConfig(); err != nil {
		t.Fatalf("operator could not start from the server bundle: %v", err)
	}
}

// operatorHTTPClient returns an mTLS client using the operator identity from
// dir, exactly like the operator console does.
func operatorHTTPClient(t *testing.T, dir string) *http.Client {
	t.Helper()
	caPEM, err := os.ReadFile(filepath.Join(dir, "operator-ca-cert.pem"))
	if err != nil {
		t.Fatalf("read operator CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("operator CA bundle is empty")
	}
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(dir, "operator-client-cert.pem"),
		filepath.Join(dir, "operator-client-key.pem"),
	)
	if err != nil {
		t.Fatalf("load operator client cert: %v", err)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      pool,
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{"http/1.1"},
			},
			ForceAttemptHTTP2: false,
		},
	}
}

func waitForTCP(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("operator server did not start on port %d", port)
}

// operatorPost sends one operator API request with the given session header.
func operatorPost(t *testing.T, client *http.Client, port int, session, api string, body any) int {
	t.Helper()
	raw, err := cbor.Marshal(body)
	if err != nil {
		t.Fatalf("marshal %s: %v", api, err)
	}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://127.0.0.1:%d/%s", port, api), bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("build %s request: %v", api, err)
	}
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("operator_session", session)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s request failed: %v", api, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// TestMultiOperatorParallelCommands runs two operators against a real mTLS
// server at the same time and verifies agent ownership plus command routing.
func TestMultiOperatorParallelCommands(t *testing.T) {
	serverDir := t.TempDir()
	setupServerWorkspace(t, serverDir)

	publishTestAgent(t, "uuid-e2e-a", "e2e-a")
	publishTestAgent(t, "uuid-e2e-b", "e2e-b")

	// A live message tunnel is what makes an operator session online and keeps
	// its agent claims from being treated as expired.
	MarkOperatorOnline("op-a")
	MarkOperatorOnline("op-b")
	t.Cleanup(func() {
		MarkOperatorOffline("op-a")
		MarkOperatorOffline("op-b")
	})

	// Capture what actually reaches each agent.
	origSend := agents.SendCmd
	t.Cleanup(func() { agents.SendCmd = origSend })
	var mu sync.Mutex
	dispatched := map[string][]string{}
	agents.SendCmd = func(cmd, jobID string, a *def.Emp3r0rAgent) error {
		mu.Lock()
		dispatched[a.Tag] = append(dispatched[a.Tag], cmd)
		mu.Unlock()
		return nil
	}

	port := freeTCPPort(t)
	go StartOperatorMTLSServer(port)
	waitForTCP(t, port)
	t.Cleanup(func() {
		if network.MTLSServer != nil && network.MTLSServerCtx != nil {
			_ = network.MTLSServer.Shutdown(network.MTLSServerCtx)
		}
	})

	client := operatorHTTPClient(t, serverDir)

	setActive := func(session, tag string) int {
		return operatorPost(t, client, port, session, transport.OperatorSetActiveAgent, def.Operation{AgentTag: tag})
	}

	// Each operator claims its own agent; a live claim by another operator is a
	// conflict even when the agent is free for the other one.
	if code := setActive("op-a", "e2e-a"); code != http.StatusOK {
		t.Fatalf("op-a claim = %d, want 200", code)
	}
	if code := setActive("op-b", "e2e-b"); code != http.StatusOK {
		t.Fatalf("op-b claim = %d, want 200", code)
	}
	if code := setActive("op-a", "e2e-b"); code != http.StatusConflict {
		t.Fatalf("op-a stealing op-b's agent = %d, want 409", code)
	}

	// Dispatch in parallel: A only ever commands e2e-a, B only e2e-b.
	const rounds = 25
	var wg sync.WaitGroup
	send := func(session, tag, cmd string) {
		defer wg.Done()
		jobID := uuid.NewString()
		command := cmd
		code := operatorPost(t, client, port, session, transport.OperatorSendCommand, def.Operation{
			AgentTag: tag,
			Action:   "command",
			Command:  &command,
			JobID:    &jobID,
		})
		if code != http.StatusOK {
			t.Errorf("send_command %s on %s = %d, want 200", session, tag, code)
		}
	}
	for i := range rounds {
		wg.Add(2)
		go send("op-a", "e2e-a", fmt.Sprintf("a-%d", i))
		go send("op-b", "e2e-b", fmt.Sprintf("b-%d", i))
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(dispatched["e2e-a"]) != rounds || len(dispatched["e2e-b"]) != rounds {
		t.Fatalf("commands dispatched = %d/%d, want %d/%d",
			len(dispatched["e2e-a"]), len(dispatched["e2e-b"]), rounds, rounds)
	}
	for _, cmd := range dispatched["e2e-a"] {
		if !strings.HasPrefix(cmd, "a-") {
			t.Fatalf("cross-talk: e2e-a received %q", cmd)
		}
	}
	for _, cmd := range dispatched["e2e-b"] {
		if !strings.HasPrefix(cmd, "b-") {
			t.Fatalf("cross-talk: e2e-b received %q", cmd)
		}
	}

	// Ownership is reported on the agent-list snapshot as well.
	list := agents.GetConnectedAgents()
	owners := map[string]string{}
	for _, a := range list {
		owners[a.Tag] = agentLockOwner(a.UUID)
	}
	if owners["e2e-a"] != "op-a" || owners["e2e-b"] != "op-b" {
		t.Fatalf("agent owners = %v, want e2e-a:op-a e2e-b:op-b", owners)
	}

	// The server audit log records who operated what target.
	audit, err := os.ReadFile(filepath.Join(serverDir, operatorAuditFileName))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	auditText := string(audit)
	for _, want := range []string{
		`operator="op-a"`,
		`operator="op-b"`,
		`action="claim"`,
		`action="command"`,
		`uuid-e2e-a`,
		`uuid-e2e-b`,
	} {
		if !strings.Contains(auditText, want) {
			t.Errorf("audit log missing %s", want)
		}
	}
}

// TestMultiOperatorMessageTunnelRouting verifies that two live operator
// tunnels coexist and that broadcasts reach both while targeted frames reach
// only the addressed operator.
func TestMultiOperatorMessageTunnelRouting(t *testing.T) {
	connA, peerA := net.Pipe()
	connB, peerB := net.Pipe()
	t.Cleanup(func() {
		_ = connA.Close()
		_ = connB.Close()
		_ = peerA.Close()
		_ = peerB.Close()
	})

	RegisterOperatorConn("route-a", connA)
	RegisterOperatorConn("route-b", connB)
	t.Cleanup(func() {
		MarkOperatorOffline("route-a")
		MarkOperatorOffline("route-b")
	})

	read := func(conn net.Conn) <-chan def.MsgTunData {
		ch := make(chan def.MsgTunData, 4)
		go func() {
			dec := cbor.NewDecoder(conn)
			for {
				var m def.MsgTunData
				if err := dec.Decode(&m); err != nil {
					return
				}
				ch <- m
			}
		}()
		return ch
	}
	outA, outB := read(peerA), read(peerB)

	// Broadcast reaches both operators.
	if err := fwdMsg2Operators(def.MsgTunData{Tag: "SUCCESS", Response: []byte("broadcast")}); err != nil {
		t.Fatalf("broadcast: %v", err)
	}
	for name, ch := range map[string]<-chan def.MsgTunData{"route-a": outA, "route-b": outB} {
		select {
		case m := <-ch:
			if m.Tag != "SUCCESS" {
				t.Fatalf("broadcast to %s has tag %q", name, m.Tag)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("broadcast not received by %s", name)
		}
	}

	// A targeted frame reaches only its recipient.
	if err := fwdMsgToOperator("route-a", def.MsgTunData{Tag: "INFO", Response: []byte("dm")}); err != nil {
		t.Fatalf("targeted send: %v", err)
	}
	select {
	case m := <-outA:
		if m.Tag != "INFO" {
			t.Fatalf("targeted frame has tag %q", m.Tag)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("targeted frame not received by route-a")
	}
	select {
	case m := <-outB:
		t.Fatalf("route-b received a frame addressed to route-a: %#v", m)
	case <-time.After(200 * time.Millisecond):
	}
}
