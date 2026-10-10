//go:build !linux && !windows && !darwin

package util

// GetUptime returns system uptime
func GetUptime() string {
	return "N/A"
}
