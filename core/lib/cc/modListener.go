//go:build linux
// +build linux

package cc

import (
	"fmt"

	"github.com/fatih/color"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
)

func modListener() {
	if Options["listener"] == nil || Options["port"] == nil || Options["payload"] == nil || Options["compression"] == nil || Options["passphrase"] == nil {
		CliPrintError("One or more required options are nil")
		return
	}
	cmd := fmt.Sprintf("%s --listener %s --port %s --payload %s --compression %s --passphrase %s",
		emp3r0r_def.C2CmdListener,
		Options["listener"].Val,
		Options["port"].Val,
		Options["payload"].Val,
		Options["compression"].Val,
		Options["passphrase"].Val)
	err := SendCmd(cmd, "", CurrentTarget)
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
	color.HiMagenta("Please wait for agent's response...")
}
