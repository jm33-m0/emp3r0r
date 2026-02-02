//go:build !linux && !windows
// +build !linux,!windows

package util

// GetMachineID retrieves the unique machine identifier
func GetMachineID() string {
	// Fallback to MAC-based ID
	return genShortID()
}
