//go:build windows

package modules

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/priv"
	"golang.org/x/sys/windows"
)

// executeWithToken runs action under the impersonation context of the token
// identified by sid in priv.TokenMap. If sid is empty the action is called
// directly (no impersonation). Returns an error if the SID is not found in
// the map or if ExecuteAsToken itself fails.
func executeWithToken(sid string, action func() error) error {
	if sid == "" {
		return action()
	}

	raw, ok := priv.TokenMap.Load(sid)
	if !ok {
		return fmt.Errorf("token not found for SID %q – steal a token first with steal-token", sid)
	}

	hToken, ok := raw.(windows.Handle)
	if !ok {
		return fmt.Errorf("invalid token handle type for SID %q", sid)
	}

	return priv.ExecuteAsToken(hToken, action)
}
