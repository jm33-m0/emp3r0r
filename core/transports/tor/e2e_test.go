//go:build linux && cgo

package tor_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/paths"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/builder"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/server"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/pkg/transportbridge"
)

// The Tor end-to-end tests run the real Tor daemon, the real C2 dispatcher,
// and a real agent process. They are opt-in because they need Tor installed
// and a working Tor network:
//
//	EMP3R0R_TOR_INTEGRATION=1 TOR_BIN=/path/to/tor go test -v \
//	  -run 'TestTorCustomC2EndToEnd' ./transports/tor
//
// TOR_LIBDIR may point at a directory containing libevent for a locally
// extracted Tor package.

type torE2EEnv struct {
	tmpDir     string
	caKeyFile  string
	caPEM      []byte
	routes     def.C2Routing
	bridgeAddr string
	onion      string
	socksPort  int
	torOut     *bytes.Buffer
}

func TestTorCustomC2EndToEnd(t *testing.T) {
	env := setupTorE2E(t)

	agentPath := filepath.Join(env.tmpDir, "agent")
	buildAgentForTor(t, agentPath)

	agentUUID := uuid.NewString()
	agentSigB64, err := signUUID(agentUUID, env.caKeyFile)
	if err != nil {
		t.Fatalf("sign UUID: %v", err)
	}
	agentSig, err := base64.URLEncoding.DecodeString(agentSigB64)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	agentCfg := &def.Config{
		CCAddress:        env.onion + ":80",
		C2ChannelMode:    "tor",
		TransportOptions: map[string]string{"socks5": fmt.Sprintf("127.0.0.1:%d", env.socksPort)},
		C2Routes:         env.routes,
		AgentUUID:        agentUUID,
		AgentUUIDSig:     agentSig,
		AgentTag:         agentUUID,
		CAPEM:            string(env.caPEM),
		PollInterval:     1,
		PollWindow:       1,
		Jitter:           0,
		CCTimeout:        2000,
	}
	cborCfg, err := cbor.Marshal(agentCfg)
	if err != nil {
		t.Fatalf("marshal agent config: %v", err)
	}
	encCfg, err := crypto.AES_GCM_Encrypt([]byte(def.MagicString), cborCfg)
	if err != nil {
		t.Fatalf("encrypt agent config: %v", err)
	}
	patchedAgent := filepath.Join(env.tmpDir, "agent-patched")
	if err := builder.PatchAgentBinary(agentPath, patchedAgent, encCfg); err != nil {
		t.Fatalf("patch agent: %v", err)
	}

	done, out := startTorAgent(t, patchedAgent, env)
	waitForTorCheckin(t, agentUUID, done, out, env)
}

func TestTorCustomC2EndToEndC(t *testing.T) {
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skip("zig is required to build the C agent")
	}
	env := setupTorE2E(t)

	mode := "tor"
	address := env.onion + ":80"
	interval, window, jitter := 1, 1, 0
	res, err := builder.GenerateCAgentWorkflow(builder.AgentConfig{
		CCAddress:            &address,
		C2ChannelMode:        &mode,
		AllowCustomTransport: true,
		TransportOptions:     map[string]string{"socks5": fmt.Sprintf("127.0.0.1:%d", env.socksPort)},
		PollInterval:         &interval,
		PollWindow:           &window,
		Jitter:               &jitter,
	}, builder.CAgentProviders{
		Transport:            "tor",
		Dynload:              "auto",
		AllowCustomTransport: true,
	}, func(agentUUID string) (string, error) {
		return signUUID(agentUUID, env.caKeyFile)
	})
	if err != nil {
		t.Fatalf("build C agent with Tor transport: %v", err)
	}

	done, out := startTorAgent(t, res.OutputFile, env)
	waitForTorCheckin(t, res.AgentUUID, done, out, env)
}

func setupTorE2E(t *testing.T) *torE2EEnv {
	t.Helper()
	if os.Getenv("EMP3R0R_TOR_INTEGRATION") != "1" {
		t.Skip("set EMP3R0R_TOR_INTEGRATION=1 to run the real Tor integration test")
	}
	torBin := os.Getenv("TOR_BIN")
	if torBin == "" {
		t.Skip("set TOR_BIN to the Tor executable")
	}
	if _, err := os.Stat(torBin); err != nil {
		t.Fatalf("TOR_BIN: %v", err)
	}
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("Skipping test: race detector is enabled")
	}

	coreDir, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve core dir: %v", err)
	}
	origRuntime := live.GetRuntimeConfig()
	origWorkSpace := live.EmpWorkSpace
	origDataDir := live.EmpDataDir
	origConfigFile := live.EmpConfigFile
	origWWWRoot := paths.WWWRoot
	origCACrtPEM := transport.GetCACrtPEM()
	origCaKeyFile := transport.CaKeyFile

	tmpDir, err := os.MkdirTemp("", "emp3r0r-tor-e2e-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	keep := os.Getenv("EMP3R0R_TOR_KEEP") == "1"
	if keep {
		t.Logf("keeping test directory: %s", tmpDir)
	}
	t.Cleanup(func() {
		live.SetRuntimeConfig(origRuntime)
		live.EmpWorkSpace = origWorkSpace
		live.EmpDataDir = origDataDir
		live.EmpConfigFile = origConfigFile
		paths.WWWRoot = origWWWRoot
		transport.SetCACrtPEM(origCACrtPEM)
		transport.CaKeyFile = origCaKeyFile
		if !keep {
			_ = os.RemoveAll(tmpDir)
		}
	})

	live.EmpWorkSpace = tmpDir
	live.EmpDataDir = coreDir
	live.EmpConfigFile = filepath.Join(tmpDir, "emp3r0r.json")
	paths.WWWRoot = filepath.Join(tmpDir, "www")
	if err := os.MkdirAll(paths.WWWRoot, 0o700); err != nil {
		t.Fatalf("create WWW root: %v", err)
	}

	caCertFile := filepath.Join(tmpDir, "ca-cert.pem")
	caKeyFile := filepath.Join(tmpDir, "ca-key.pem")
	if _, err := transport.GenCerts(nil, caCertFile, caKeyFile, "", "", true); err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	transport.CaKeyFile = caKeyFile
	caPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	transport.SetCACrtPEM(caPEM)

	routes := def.C2Routing{
		Checkin: "c2-checkin",
		Msg:     "c2-msg",
		FTP:     "c2-ftp",
		WWW:     "c2-www",
		Proxy:   "c2-proxy",
	}
	socket := filepath.Join(tmpDir, "bridge.sock")
	live.SetRuntimeConfig(&def.Config{
		BridgeSocket:  socket,
		C2ChannelMode: "tor",
		C2Routes:      routes,
		CAPEM:         string(caPEM),
	})

	if err := agents.InitAgentDB(filepath.Join(tmpDir, "agents.db")); err != nil {
		t.Fatalf("InitAgentDB: %v", err)
	}
	live.ClearAgents()
	t.Cleanup(func() {
		_ = agents.CloseAgentDB()
		live.ClearAgents()
	})

	const operator = "tor-integration"
	server.MarkOperatorOnline(operator)
	t.Cleanup(func() { server.MarkOperatorOffline(operator) })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = server.StartC2BridgeListener(ctx) }()
	waitForSocket(t, socket)

	bridgeListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen bridge: %v", err)
	}
	t.Cleanup(func() { _ = bridgeListener.Close() })
	go func() {
		_ = transportbridge.Serve(ctx, bridgeListener, transportbridge.Config{
			Transport: "tor",
			C2Socket:  socket,
		})
	}()
	bridgeAddr := bridgeListener.Addr().String()

	torData := filepath.Join(tmpDir, "tor-data")
	torHidden := filepath.Join(tmpDir, "tor-hidden")
	for _, dir := range []string{torData, torHidden} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
	}
	socksPort := freeTCPPort(t)
	torLog := filepath.Join(tmpDir, "tor.log")
	torrc := fmt.Sprintf(`SocksPort 127.0.0.1:%d
DataDirectory %s
HiddenServiceDir %s
HiddenServicePort 80 %s
Log notice file %s
`, socksPort, torData, torHidden, bridgeAddr, torLog)
	torrcPath := filepath.Join(tmpDir, "torrc")
	if err := os.WriteFile(torrcPath, []byte(torrc), 0o600); err != nil {
		t.Fatalf("write torrc: %v", err)
	}

	torCmd := exec.Command(torBin, "-f", torrcPath)
	torCmd.Env = os.Environ()
	if libdir := os.Getenv("TOR_LIBDIR"); libdir != "" {
		torCmd.Env = append(torCmd.Env, "LD_LIBRARY_PATH="+libdir)
	}
	var torOut bytes.Buffer
	torCmd.Stdout = &torOut
	torCmd.Stderr = &torOut
	if err := torCmd.Start(); err != nil {
		t.Fatalf("start tor: %v", err)
	}
	t.Cleanup(func() {
		_ = torCmd.Process.Kill()
		_, _ = torCmd.Process.Wait()
	})

	return &torE2EEnv{
		tmpDir:     tmpDir,
		caKeyFile:  caKeyFile,
		caPEM:      caPEM,
		routes:     routes,
		bridgeAddr: bridgeAddr,
		onion:      waitForTor(t, torHidden, torLog, &torOut),
		socksPort:  socksPort,
		torOut:     &torOut,
	}
}

func startTorAgent(t *testing.T, path string, env *torE2EEnv) (<-chan error, *bytes.Buffer) {
	t.Helper()
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatalf("chmod agent: %v", err)
	}
	agentCmd := exec.Command(path)
	agentCmd.Env = append(os.Environ(), "HOME="+env.tmpDir)
	out := &bytes.Buffer{}
	agentCmd.Stdout = out
	agentCmd.Stderr = out
	if err := agentCmd.Start(); err != nil {
		t.Fatalf("start agent: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- agentCmd.Wait() }()
	t.Cleanup(func() {
		_ = agentCmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	return done, out
}

func waitForTorCheckin(t *testing.T, agentUUID string, done <-chan error, out *bytes.Buffer, env *torE2EEnv) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if agents.GetAgentByUUID(agentUUID) != nil {
			logging.Successf("agent %s checked in over real Tor", agentUUID)
			return
		}
		select {
		case err := <-done:
			t.Fatalf("agent exited before check-in: %v\nagent output:\n%s\ntor output:\n%s", err, out.String(), env.torOut.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent did not check in over Tor within 3m\nagent output:\n%s\ntor output:\n%s", out.String(), env.torOut.String())
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// signUUID signs the agent UUID with the CA private key.
func signUUID(uuidStr, keyFile string) (string, error) {
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return "", fmt.Errorf("decode CA key PEM")
	}
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(uuidStr))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return "", err
	}
	sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(sig), nil
}

// freeTCPPort returns a currently free loopback TCP port.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("socket %s was not created", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func waitForTor(t *testing.T, hiddenDir, logPath string, output *bytes.Buffer) string {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		hostname, err := os.ReadFile(filepath.Join(hiddenDir, "hostname"))
		if err == nil && strings.HasSuffix(strings.TrimSpace(string(hostname)), ".onion") {
			if torBootstrapped(logPath) {
				return strings.TrimSpace(string(hostname))
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("Tor did not bootstrap\noutput:\n%s", output.String())
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func torBootstrapped(logPath string) bool {
	data, err := os.ReadFile(logPath)
	if err != nil {
		return false
	}
	return bytes.Contains(data, []byte("Bootstrapped 100%"))
}

func buildAgentForTor(t *testing.T, output string) {
	t.Helper()
	buildScript, err := filepath.Abs("../../build.py")
	if err != nil {
		t.Fatalf("resolve build.py: %v", err)
	}
	cmd := exec.Command("python3", buildScript,
		"--build-payload",
		"--payload-kind", "pure",
		"--payload-os", "linux",
		"--payload-arch", "amd64",
		"--payload-output", output,
		"--payload-magic-string", def.MagicString,
		"--agent-tags", "with_transport_tor",
	)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "EMP3R0R_DISABLE_GARBLE=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build Tor agent: %v\n%s", err, out)
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatalf("Tor agent was not built: %v\n%s", err, out)
	}
}
