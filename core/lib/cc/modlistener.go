package cc

import (
	"fmt"

	"github.com/fatih/color"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
)

func modListener() {
	if AvailableModuleOptions["listener"] == nil || AvailableModuleOptions["port"] == nil || AvailableModuleOptions["payload"] == nil || AvailableModuleOptions["compression"] == nil || AvailableModuleOptions["passphrase"] == nil {
		LogError("One or more required options are nil")
		return
	}
	cmd := fmt.Sprintf("%s --listener %s --port %s --payload %s --compression %s --passphrase %s",
		emp3r0r_def.C2CmdListener,
		AvailableModuleOptions["listener"].Val,
		AvailableModuleOptions["port"].Val,
		AvailableModuleOptions["payload"].Val,
		AvailableModuleOptions["compression"].Val,
		AvailableModuleOptions["passphrase"].Val)
	err := SendCmd(cmd, "", ActiveAgent)
	if err != nil {
		LogError("SendCmd: %v", err)
		return
	}
	color.HiMagenta("Please wait for agent's response...")
}
