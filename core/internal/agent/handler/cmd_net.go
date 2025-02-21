package handler

import (
	"github.com/jm33-m0/emp3r0r/core/internal/agent/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/c2transport"
	"github.com/spf13/cobra"
)

// netHelperCmdRun displays network information.
func netHelperCmdRun(cmd *cobra.Command, args []string) {
	// Assume shellNet() exists and returns network info.
	out := agentutils.CmdNetHelper()
	c2transport.C2RespPrintf(cmd, "%s", out)
}
