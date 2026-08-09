//go:build !windows

package modules

// executeWithToken is a no-op stub on non-Windows platforms.
// It runs action directly without any impersonation.
func executeWithToken(_ string, action func() error) error {
	return action()
}
