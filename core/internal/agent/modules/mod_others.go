//go:build !windows

package modules

// executeWithToken is a no-op stub on non-Windows platforms.
// It runs action directly without any impersonation, passing token=0.
func executeWithToken(_ string, action func(token uintptr) error) error {
	return action(0)
}
