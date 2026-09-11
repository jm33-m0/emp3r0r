package handler

import (
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/spf13/cobra"
)

// suicideCmdRun terminates the agent process on operator request.
func suicideCmdRun(cmd *cobra.Command, args []string) {
	if len(args) != 0 {
		c2transport.NotifyC2(cmd, "args error: %v", args)
		return
	}
	c2transport.NotifyC2(cmd, "Exiting")
	logging.Infof("Exiting...")
	live.Exit(0)
}
