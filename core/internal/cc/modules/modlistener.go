package modules

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/runtime_def"
	"github.com/jm33-m0/emp3r0r/core/internal/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/internal/logging"
)

func modListener() {
	if runtime_def.AvailableModuleOptions["listener"] == nil || runtime_def.AvailableModuleOptions["port"] == nil || runtime_def.AvailableModuleOptions["payload"] == nil || runtime_def.AvailableModuleOptions["compression"] == nil || runtime_def.AvailableModuleOptions["passphrase"] == nil {
		logging.Errorf("One or more required options are nil")
		return
	}
	cmd := fmt.Sprintf("%s --listener %s --port %s --payload %s --compression %s --passphrase %s",
		emp3r0r_def.C2CmdListener,
		runtime_def.AvailableModuleOptions["listener"].Val,
		runtime_def.AvailableModuleOptions["port"].Val,
		runtime_def.AvailableModuleOptions["payload"].Val,
		runtime_def.AvailableModuleOptions["compression"].Val,
		runtime_def.AvailableModuleOptions["passphrase"].Val)
	err := agents.SendCmd(cmd, "", runtime_def.ActiveAgent)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
	color.HiMagenta("Please wait for agent's response...")
}
