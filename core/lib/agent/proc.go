package agent

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// CheckAgentProcess fill up info.AgentProcess
func CheckAgentProcess() *AgentProcess {
	p := &AgentProcess{}
	p.PID = os.Getpid()
	p.PPID = os.Getppid()
	p.Cmdline = util.ProcCmdline(p.PID)
	p.Parent = util.ProcCmdline(p.PPID)

	return p
}

// UpdateHIDE_PIDS update HIDE PID list
func UpdateHIDE_PIDS() error {
	HIDE_PIDS = util.RemoveDupsFromArray(HIDE_PIDS)
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
