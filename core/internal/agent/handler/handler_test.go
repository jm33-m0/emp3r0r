package handler

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/txthinking/socks5"
)

func TestKillCmdRun(t *testing.T) {
	// Initialize RuntimeConfig if needed
	if common.RuntimeConfig == nil {
		common.RuntimeConfig = &def.Config{}
	}
	common.RuntimeConfig.AgentTag = "test-agent"

	// Mock C2 connection
	var mockConn bytes.Buffer
	c2transport.Connection = &mockConn
	defer func() { c2transport.Connection = nil }()

	// Start a dummy process using the test binary itself
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start dummy process: %v", err)
	}
	pid := cmd.Process.Pid

	// Ensure cleanup in case test fails
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()

	// Get the root command
	rootCmd := CoreCommands()

	// Execute kill command
	rootCmd.SetArgs([]string{"kill", fmt.Sprintf("%d", pid)})

	// Execute
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute kill command: %v", err)
	}

	// Verify process is killed
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-done:
		// Process exited successfully (or with error, but it exited)
	case <-time.After(2 * time.Second):
		t.Errorf("Process %d did not exit after kill command", pid)
	}

	// Verify response
	output := mockConn.String()
	t.Logf("C2 Output: %s", output)
}

func TestLsCmdRun(t *testing.T) {
	// Initialize RuntimeConfig if needed
	if common.RuntimeConfig == nil {
		common.RuntimeConfig = &def.Config{}
	}
	common.RuntimeConfig.AgentTag = "test-agent"

	// Mock C2 connection
	var mockConn bytes.Buffer
	c2transport.Connection = &mockConn
	defer func() { c2transport.Connection = nil }()

	// Create temp dir
	tmpDir := t.TempDir()
	// Create a file in it
	f, err := os.CreateTemp(tmpDir, "testfile")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Get the root command
	rootCmd := CoreCommands()

	// Execute ls command
	rootCmd.SetArgs([]string{"ls", "--dst", tmpDir})

	// Execute
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute ls command: %v", err)
	}

	// Verify response
	var msg def.MsgTunData
	if err := cbor.Unmarshal(mockConn.Bytes(), &msg); err != nil {
		t.Fatalf("Failed to unmarshal CBOR response: %v", err)
	}
	output := string(msg.Response)
	t.Logf("C2 Output: %s", output)
	if !strings.Contains(output, filepath.Base(f.Name())) {
		t.Errorf("Output does not contain created file: %s", output)
	}
}

func TestPsCmdRun(t *testing.T) {
	// Initialize RuntimeConfig if needed
	if common.RuntimeConfig == nil {
		common.RuntimeConfig = &def.Config{}
	}
	common.RuntimeConfig.AgentTag = "test-agent"

	// Mock C2 connection
	var mockConn bytes.Buffer
	c2transport.Connection = &mockConn
	defer func() { c2transport.Connection = nil }()

	// Get the root command
	rootCmd := CoreCommands()

	// Execute ps command
	rootCmd.SetArgs([]string{"ps"})

	// Execute
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute ps command: %v", err)
	}

	// Verify response
	var msg def.MsgTunData
	if err := cbor.Unmarshal(mockConn.Bytes(), &msg); err != nil {
		t.Fatalf("Failed to unmarshal CBOR response: %v", err)
	}

	// Decode the inner response (which is also CBOR encoded list of processes)
	var procs []util.ProcEntry
	if err := cbor.Unmarshal([]byte(msg.Response), &procs); err != nil {
		t.Fatalf("Failed to unmarshal inner CBOR response: %v", err)
	}

	if len(procs) == 0 {
		t.Errorf("No processes returned")
	}

	found := false
	for _, p := range procs {
		if p.PID > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("No valid PID found in process list")
	}
}

func TestFsCmds(t *testing.T) {
	// Initialize RuntimeConfig if needed
	if common.RuntimeConfig == nil {
		common.RuntimeConfig = &def.Config{}
	}
	common.RuntimeConfig.AgentTag = "test-agent"

	// Mock C2 connection
	var mockConn bytes.Buffer
	c2transport.Connection = &mockConn
	defer func() { c2transport.Connection = nil }()

	// Create temp dir
	tmpDir := t.TempDir()

	// Get the root command
	rootCmd := CoreCommands()

	// 1. mkdir
	newDir := filepath.Join(tmpDir, "newdir")
	rootCmd.SetArgs([]string{"mkdir", "--dst", newDir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute mkdir command: %v", err)
	}
	// Verify directory exists
	if !util.IsDirExist(newDir) {
		t.Errorf("Directory %s was not created", newDir)
	}
	mockConn.Reset()

	// 2. cp
	srcFile := filepath.Join(tmpDir, "src.txt")
	if err := os.WriteFile(srcFile, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	dstFile := filepath.Join(newDir, "dst.txt")
	rootCmd.SetArgs([]string{"cp", "--src", srcFile, "--dst", dstFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute cp command: %v", err)
	}
	// Verify file exists
	if !util.IsFileExist(dstFile) {
		t.Errorf("File %s was not copied", dstFile)
	}
	mockConn.Reset()

	// 3. mv
	movedFile := filepath.Join(newDir, "moved.txt")
	rootCmd.SetArgs([]string{"mv", "--src", dstFile, "--dst", movedFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute mv command: %v", err)
	}
	// Verify file moved
	if !util.IsFileExist(movedFile) {
		t.Errorf("File %s was not moved", movedFile)
	}
	// dstFile should be gone
	if util.IsFileExist(dstFile) {
		t.Errorf("File %s still exists after move", dstFile)
	}
	mockConn.Reset()

	// 4. rm
	rootCmd.SetArgs([]string{"rm", "--dst", movedFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute rm command: %v", err)
	}
	// Verify file removed
	if util.IsFileExist(movedFile) {
		t.Errorf("File %s still exists after rm", movedFile)
	}
}

func TestCdPwdCmds(t *testing.T) {
	// Initialize RuntimeConfig if needed
	if common.RuntimeConfig == nil {
		common.RuntimeConfig = &def.Config{}
	}
	common.RuntimeConfig.AgentTag = "test-agent"

	// Mock C2 connection
	var mockConn bytes.Buffer
	c2transport.Connection = &mockConn
	defer func() { c2transport.Connection = nil }()

	// Create temp dir
	tmpDir := t.TempDir()

	// Save current WD and restore it after test
	wd, _ := os.Getwd()
	defer os.Chdir(wd)

	// Get the root command
	rootCmd := CoreCommands()

	// 1. pwd initial
	rootCmd.SetArgs([]string{"pwd"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute pwd command: %v", err)
	}
	var msg def.MsgTunData
	if err := cbor.Unmarshal(mockConn.Bytes(), &msg); err != nil {
		t.Fatalf("Failed to unmarshal CBOR response: %v", err)
	}
	initialPwd := string(msg.Response)
	t.Logf("Initial PWD: %s", initialPwd)
	mockConn.Reset()

	// 2. cd to temp dir
	rootCmd.SetArgs([]string{"cd", "--dst", tmpDir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute cd command: %v", err)
	}
	mockConn.Reset()

	// 3. pwd check
	rootCmd.SetArgs([]string{"pwd"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute pwd command: %v", err)
	}
	if err := cbor.Unmarshal(mockConn.Bytes(), &msg); err != nil {
		t.Fatalf("Failed to unmarshal CBOR response: %v", err)
	}
	newPwd := string(msg.Response)
	t.Logf("New PWD: %s", newPwd)

	// Check if new pwd contains tmpDir
	// Note: /tmp might be a symlink, so we use EvalSymlinks
	realTmpDir, _ := filepath.EvalSymlinks(tmpDir)
	if !strings.Contains(newPwd, realTmpDir) && !strings.Contains(newPwd, tmpDir) {
		t.Errorf("PWD did not change to %s. Got: %s", tmpDir, newPwd)
	}
}

func TestNetHelperCmdRun(t *testing.T) {
	// Setup mock C2
	var buf bytes.Buffer
	c2transport.Connection = &buf
	defer func() { c2transport.Connection = nil }()

	// Get the root command
	rootCmd := CoreCommands()

	// Run net_helper command
	rootCmd.SetArgs([]string{"net_helper"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute net_helper command: %v", err)
	}

	// Check output
	var msg def.MsgTunData
	if err := cbor.Unmarshal(buf.Bytes(), &msg); err != nil {
		t.Fatalf("Failed to unmarshal CBOR response: %v", err)
	}

	// Check cmd_slice
	found := false
	for _, cmd := range msg.CmdSlice {
		if cmd == "net_helper" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected CmdSlice to contain 'net_helper', got: %v", msg.CmdSlice)
	}

	// And some network info, e.g. "ip addr"
	if !strings.Contains(string(msg.Response), "ip addr") {
		t.Errorf("Expected output to contain 'ip addr', got: %s", msg.Response)
	}
}

func TestExecCmdRun(t *testing.T) {
	// Setup mock C2
	var buf bytes.Buffer
	c2transport.Connection = &buf
	defer func() { c2transport.Connection = nil }()

	// Get the root command
	rootCmd := CoreCommands()

	// Run exec command: echo hello
	// Note: exec command uses util.ParseCmd to parse the command string.
	// The command string is passed via --cmd flag.
	rootCmd.SetArgs([]string{"exec", "--cmd", "echo hello"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute exec command: %v", err)
	}

	// Check output
	var msg def.MsgTunData
	if err := cbor.Unmarshal(buf.Bytes(), &msg); err != nil {
		t.Fatalf("Failed to unmarshal CBOR response: %v", err)
	}

	found := false
	for _, cmd := range msg.CmdSlice {
		if cmd == "exec" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected CmdSlice to contain 'exec', got: %v", msg.CmdSlice)
	}

	// The output of echo hello should be in the response data
	if !strings.Contains(string(msg.Response), "hello") {
		t.Errorf("Expected output to contain 'hello', got: %s", msg.Response)
	}
}

func TestGetCmdRun_Dir(t *testing.T) {
	// Setup mock C2
	var buf bytes.Buffer
	c2transport.Connection = &buf
	defer func() { c2transport.Connection = nil }()

	// Create temp dir with files
	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, "f1.txt")
	f2 := filepath.Join(tmpDir, "f2.txt")
	if err := os.WriteFile(f1, []byte("content1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f2, []byte("content2"), 0600); err != nil {
		t.Fatal(err)
	}

	// Get the root command
	rootCmd := CoreCommands()

	// Run get command on directory
	// Note: get command uses --file_path flag
	// We also need to provide token and offset to pass validation
	rootCmd.SetArgs([]string{"get", "--file_path", tmpDir, "--token", "test-token", "--offset", "0"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute get command: %v", err)
	}

	// Check output
	var msg def.MsgTunData
	if err := cbor.Unmarshal(buf.Bytes(), &msg); err != nil {
		t.Fatalf("Failed to unmarshal CBOR response: %v", err)
	}
	output := string(msg.Response)
	t.Logf("C2 Output: %s", output)

	// Expect file list
	if !strings.Contains(output, f1) || !strings.Contains(output, f2) {
		t.Errorf("Expected output to contain file paths %s and %s, got: %s", f1, f2, output)
	}
}

func TestProxyCmd(t *testing.T) {
	if common.RuntimeConfig == nil {
		common.RuntimeConfig = &def.Config{}
	}
	common.RuntimeConfig.ShadowsocksLocalSocksPort = "1080"
	common.RuntimeConfig.Password = "password"

	var mockConn bytes.Buffer
	c2transport.Connection = &mockConn
	defer func() { c2transport.Connection = nil }()

	rootCmd := C2Commands()

	// Initialize def.ProxyServer
	// Use a random port to avoid conflicts
	port := "54321"
	addr := "127.0.0.1:" + port
	var err error
	def.ProxyServer, err = socks5.NewClassicServer(addr, "", "", "", 0, 0)
	if err != nil {
		t.Fatalf("Failed to create mock socks5 server: %v", err)
	}

	// Test Proxy On
	rootCmd.SetArgs([]string{def.C2CmdProxy, "--mode", "on", "--addr", addr})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute proxy command: %v", err)
	}

	// Wait for goroutine to start and port to be open
	for i := 0; i < 20; i++ {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	var msg def.MsgTunData
	if err := cbor.Unmarshal(mockConn.Bytes(), &msg); err != nil {
		t.Fatalf("Failed to unmarshal CBOR response: %v", err)
	}
	output := string(msg.Response)
	if !strings.Contains(output, "Socks5Proxy server ready") {
		t.Errorf("Expected 'Socks5Proxy server ready', got '%s'", output)
	}
	mockConn.Reset()

	// Wait for connections to settle before shutting down to avoid race in socks5 library
	time.Sleep(1 * time.Second)

	// Test Proxy Off
	rootCmd.SetArgs([]string{def.C2CmdProxy, "--mode", "off", "--addr", addr})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute proxy command: %v", err)
	}
	// Wait for server to shutdown
	time.Sleep(1 * time.Second)

	if err := cbor.Unmarshal(mockConn.Bytes(), &msg); err != nil {
		t.Fatalf("Failed to unmarshal CBOR response: %v", err)
	}
	output = string(msg.Response)
	if !strings.Contains(output, "Socks5Proxy server ready") {
		t.Errorf("Expected 'Socks5Proxy server ready' (stopping), got '%s'", output)
	}
}

func TestPortFwdCmd(t *testing.T) {
	if common.RuntimeConfig == nil {
		common.RuntimeConfig = &def.Config{}
	}

	var mockConn bytes.Buffer
	c2transport.Connection = &mockConn
	defer func() { c2transport.Connection = nil }()

	rootCmd := C2Commands()

	// Test PortFwd Reverse
	port := "54322"
	rootCmd.SetArgs([]string{def.C2CmdPortFwd, "--to", port, "--shID", "test-session", "--operation", "reverse"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute port_fwd command: %v", err)
	}

	var msg def.MsgTunData
	if err := cbor.Unmarshal(mockConn.Bytes(), &msg); err != nil {
		t.Fatalf("Failed to unmarshal CBOR response: %v", err)
	}
	output := string(msg.Response)
	if !strings.Contains(output, "Port forwarding started successfully") {
		t.Errorf("Expected 'Port forwarding started successfully', got '%s'", output)
	}
	mockConn.Reset()

	// Stop it
	rootCmd.SetArgs([]string{def.C2CmdPortFwd, "--to", port, "--shID", "test-session", "--operation", "stop"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute port_fwd stop command: %v", err)
	}

	if err := cbor.Unmarshal(mockConn.Bytes(), &msg); err != nil {
		t.Fatalf("Failed to unmarshal CBOR response: %v", err)
	}
	output = string(msg.Response)
	if !strings.Contains(output, "stopped") {
		t.Errorf("Expected 'stopped', got '%s'", output)
	}
}

// Helper process for TestKillCmdRun
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	time.Sleep(100 * time.Second)
	os.Exit(0)
}
