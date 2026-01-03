package handler

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
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

	// Start a dummy process
	cmd := exec.Command("sleep", "100")
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
	output := mockConn.String()
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
	output := mockConn.String()
	t.Logf("C2 Output: %s", output)
	// Check for common process columns or current process
	if !strings.Contains(output, "\\\"pid\\\":") {
		t.Errorf("Output does not contain pid field: %s", output)
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
	if _, err := os.Stat(newDir); os.IsNotExist(err) {
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
	if _, err := os.Stat(dstFile); os.IsNotExist(err) {
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
	if _, err := os.Stat(movedFile); os.IsNotExist(err) {
		t.Errorf("File %s was not moved", movedFile)
	}
	if _, err := os.Stat(dstFile); !os.IsNotExist(err) {
		t.Errorf("File %s still exists after move", dstFile)
	}
	mockConn.Reset()

	// 4. rm
	rootCmd.SetArgs([]string{"rm", "--dst", movedFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute rm command: %v", err)
	}
	// Verify file removed
	if _, err := os.Stat(movedFile); !os.IsNotExist(err) {
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

	// Get the root command
	rootCmd := CoreCommands()

	// 1. pwd initial
	rootCmd.SetArgs([]string{"pwd"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Failed to execute pwd command: %v", err)
	}
	initialPwd := mockConn.String()
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
	newPwd := mockConn.String()
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
	output := buf.String()
	t.Logf("C2 Output: %s", output)

	// We expect some JSON output with "cmd_slice": ["net_helper"]
	if !strings.Contains(output, `"cmd_slice":["net_helper"]`) {
		t.Errorf("Expected output to contain '\"cmd_slice\":[\"net_helper\"]', got: %s", output)
	}
	// And some network info, e.g. "ip addr"
	if !strings.Contains(output, "ip addr") {
		t.Errorf("Expected output to contain 'ip addr', got: %s", output)
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
	output := buf.String()
	t.Logf("C2 Output: %s", output)

	if !strings.Contains(output, `"cmd_slice":["exec"]`) {
		t.Errorf("Expected output to contain '\"cmd_slice\":[\"exec\"]', got: %s", output)
	}

	// The output of echo hello should be in the response data
	if !strings.Contains(output, "hello") {
		t.Errorf("Expected output to contain 'hello', got: %s", output)
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
	output := buf.String()
	t.Logf("C2 Output: %s", output)

	// Expect file list
	// The output is JSON stringified in the "data" field.
	if !strings.Contains(output, f1) || !strings.Contains(output, f2) {
		t.Errorf("Expected output to contain file paths %s and %s, got: %s", f1, f2, output)
	}
}
