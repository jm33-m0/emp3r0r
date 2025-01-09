//go:build linux
// +build linux

package cc

import (
	"fmt"

	"github.com/fatih/color"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
)

func moduleFileServer() {
	switchOpt, ok := Options["switch"]
	if !ok {
		CliPrintError("Option 'switch' not found")
		return
	}
	server_switch := switchOpt.Val

	portOpt, ok := Options["port"]
	if !ok {
		CliPrintError("Option 'port' not found")
		return
	}
	cmd := fmt.Sprintf("%s --port %s --switch %s", emp3r0r_data.C2CmdFileServer, portOpt.Val, server_switch)
	err := SendCmd(cmd, "", CurrentTarget)
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
	CliPrintInfo("File server is now %s", color.HiGreenString(server_switch))
}

func moduleDownloader() {
	CliPrintError("Not implemented yet")
}
