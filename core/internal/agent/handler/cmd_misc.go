package handler

import (
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
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
	logging.Infof("Exiting...")
	os.Exit(0)
}
