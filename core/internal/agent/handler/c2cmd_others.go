//go:build !windows

package handler

import (
	"github.com/spf13/cobra"
)

// platformCommands is the no-op hook for platforms without OS-specific
// commands. Windows contributes its commands in c2cmd_windows.go.
func platformCommands(_ *cobra.Command) {
}
