//go:build !linux
// +build !linux

package agent

import (
	"github.com/spf13/cobra"
)

const NotSupportedMsg = "not supported"

// runInjectLinux - dummy runner for non-linux targets.
func runInjectLinux(cmd *cobra.Command, args []string) {
	C2RespPrintf(cmd, "%s", NotSupportedMsg)
}

// runPersistenceLinux - dummy runner for non-linux targets.
func runPersistenceLinux(cmd *cobra.Command, args []string) {
	C2RespPrintf(cmd, "%s", NotSupportedMsg)
}

// runGetRootLinux - dummy runner for non-linux targets.
func runGetRootLinux(cmd *cobra.Command, args []string) {
	C2RespPrintf(cmd, "%s", NotSupportedMsg)
}

// runCleanLogLinux - dummy runner for non-linux targets.
func runCleanLogLinux(cmd *cobra.Command, args []string) {
	C2RespPrintf(cmd, "%s", NotSupportedMsg)
}

// runLPELinux - dummy runner for non-linux targets.
func runLPELinux(cmd *cobra.Command, args []string) {
	C2RespPrintf(cmd, "%s", NotSupportedMsg)
}

// runSSHHarvesterLinux - dummy runner for non-linux targets.
func runSSHHarvesterLinux(cmd *cobra.Command, args []string) {
	C2RespPrintf(cmd, "%s", NotSupportedMsg)
}
