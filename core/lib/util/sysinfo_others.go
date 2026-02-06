//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

package util

// GetMachineID retrieves the unique machine identifier
func GetMachineID() string {
	// Fallback to MAC-based ID
	return genShortID()
}

// GetUptime returns system uptime
func GetUptime() string {
	return "N/A"
}
