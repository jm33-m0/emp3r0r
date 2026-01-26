package agentutils

import (
	"os"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// getAgentProcess fill up info.emp3r0r_def.AgentProcess
func getAgentProcess() *def.AgentProcess {
	p := &def.AgentProcess{}
	p.PID = os.Getpid()
	p.PPID = os.Getppid()
	p.Cmdline = util.ProcCmdline(p.PID)
	p.Parent = util.ProcCmdline(p.PPID)

	return p
}
