//go:build !linux
// +build !linux

package handler

import (
	"github.com/spf13/cobra"
)

// platformCommands - dummy runner for non-linux targets.
func platformCommands(cmd *cobra.Command) {
}
