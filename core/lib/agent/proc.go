package agent

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	gops "github.com/mitchellh/go-ps"
)

// CheckAgentProcess fill up info.AgentProcess
func CheckAgentProcess() *AgentProcess {
	p := &AgentProcess{}
	p.PID = os.Getpid()
	p.PPID = os.Getppid()
	p.Cmdline = ProcCmdline(p.PID)
	p.Parent = ProcCmdline(p.PPID)

	return p
}

// ProcCmdline read cmdline data of a process
func ProcCmdline(pid int) (cmdline string) {
	data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		log.Println(err)
		return
	}
	cmdline = string(data)

	return
}

// UpdateHIDE_PIDS update HIDE PID list
func UpdateHIDE_PIDS() error {
	HIDE_PIDS = RemoveDupsFromArray(HIDE_PIDS)
	return ioutil.WriteFile(AgentRoot+"/emp3r0r_pids", []byte(strings.Join(HIDE_PIDS, "\n")), 0600)
}

// IsAgentRunningPID is there any emp3r0r agent already running?
func IsAgentRunningPID() (bool, int) {
	defer func() {
		myPIDText := strconv.Itoa(os.Getpid())
		if err := ioutil.WriteFile(PIDFile, []byte(myPIDText), 0600); err != nil {
			log.Printf("Write PIDFile: %v", err)
		}
	}()

	pidBytes, err := ioutil.ReadFile(PIDFile)
	if err != nil {
		return false, -1
	}
	pid, err := strconv.Atoi(string(pidBytes))
	if err != nil {
		return false, -1
	}

	_, err = os.FindProcess(pid)
	return err == nil, pid
}

// ProcUID get euid of a process
func ProcUID(pid int) string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Uid:") {
			uid := strings.Fields(line)[1]
			return uid
		}
	}
	return ""
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
