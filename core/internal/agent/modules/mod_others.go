//go:build !windows

package modules

import "github.com/jm33-m0/emp3r0r/core/internal/def"

// executeWithToken is a no-op stub on non-Windows platforms.
// It runs action directly without any impersonation, passing token=0.
func executeWithToken(_ string, action func(token uintptr) error) error {
	return action(0)
}

// resolveTokenKey is a no-op stub on non-Windows platforms: --user/--ticket
// are Windows-only, so the token key is passed through unchanged.
func resolveTokenKey(invocation def.ResolvedInvocation) (string, error) {
	return invocation.Token, nil
}
