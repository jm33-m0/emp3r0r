package priv

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// SessionMap caches netlogon logon sessions created by MakeToken.
// key: session name → *LogonSession.
//
// Token and LogonID are platform-neutral representations:
//   - on Windows, Token holds the impersonation-capable token handle
//     (windows.Handle) and LogonID holds the logon session AuthenticationId
//     (windows.LUID), converted via luidToUint64 / luidFromUint64.
//   - on other platforms the session store simply stays empty (MakeToken is
//     unsupported).
var SessionMap = &sync.Map{}

// LogonSession describes a netlogon logon session created by MakeToken.
type LogonSession struct {
	Name      string  // reference name (usable via the "token" option)
	User      string  // account name
	Domain    string  // domain (or "." for a local account)
	Token     uintptr // impersonation-capable token for this session
	LogonID   uint64  // AuthenticationId (LUID) of the session's logon session
	CreatedAt time.Time

	// NetOnly is always true for sessions created by MakeToken: it uses
	// LOGON32_LOGON_NEW_CREDENTIALS (runas /netonly semantics, like Cobalt
	// Strike's make_token), so the password is never validated, the token
	// keeps the calling user's identity (whoami is unchanged) and the supplied
	// credentials are used only for outbound network connections. Kerberos
	// ticket import still works against the session's fresh LUID.
	NetOnly bool
}

// StoreSession caches a session under name in SessionMap.
func StoreSession(name string, session *LogonSession) {
	if session == nil {
		return
	}
	if strings.TrimSpace(name) == "" {
		name = DefaultSessionName(session)
	}
	session.Name = name
	SessionMap.Store(name, session)
}

// GetSession returns the session registered under name.
func GetSession(name string) (*LogonSession, bool) {
	if name == "" {
		return nil, false
	}
	val, ok := SessionMap.Load(name)
	if !ok {
		return nil, false
	}
	session, ok := val.(*LogonSession)
	return session, ok
}

// DefaultSessionName returns "DOMAIN/user" (or just "user" for local).
//
// A forward slash is used instead of Windows' backslash so the name survives
// the CC console's shell-style word splitting unquoted: typing DOMAIN/user
// keeps its separator, while DOMAIN\user would be consumed as a shell escape
// and arrive as DOMAINuser.
func DefaultSessionName(session *LogonSession) string {
	if session == nil {
		return ""
	}
	if session.Domain != "" && session.Domain != "." {
		return fmt.Sprintf("%s/%s", session.Domain, session.User)
	}
	return session.User
}

// ListSessions returns a human-readable summary of every make_token session.
func ListSessions() []string {
	var entries []string
	SessionMap.Range(func(key, value any) bool {
		session, ok := value.(*LogonSession)
		if !ok {
			return true
		}
		entries = append(entries, fmt.Sprintf("%s  %s/%s  luid=0x%08x  created=%s",
			session.Name, session.Domain, session.User,
			session.LogonID, session.CreatedAt.Format(time.RFC3339)))
		return true
	})
	return entries
}
