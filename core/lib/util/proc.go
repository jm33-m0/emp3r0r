package util

import (
	"log"
	"os"

	gops "github.com/mitchellh/go-ps"
)

// ProcCmdline read cmdline data of a process
func ProcCmdline(pid int) string {
	proc, err := gops.FindProcess(pid)
	if err != nil || proc == nil {
		log.Printf("No such process (%d): %v", pid, err)
		return "unknown_process"
	}
	return proc.Executable()
}

// IsProcAlive check if a process name exists, returns its process(es)
func IsProcAlive(procName string) (alive bool, procs []*os.Process) {
	allprocs, err := gops.Processes()
	if err != nil {
		log.Println(err)
		return
	}

	for _, p := range allprocs {
		if p.Executable() == procName {
			alive = true
			proc, err := os.FindProcess(p.Pid())
			if err != nil {
				log.Println(err)
			}
			procs = append(procs, proc)
		}
	}

	return
}

// PidOf PID of a process name
func PidOf(name string) []int {
	pids := make([]int, 1)
	allprocs, err := gops.Processes()
	if err != nil {
		log.Println(err)
		return pids
	}

	for _, p := range allprocs {
		if p.Executable() == name {
			proc, err := os.FindProcess(p.Pid())
			if err != nil {
				log.Println(err)
			}
			pids = append(pids, proc.Pid)
		}
	}

	return pids
}
