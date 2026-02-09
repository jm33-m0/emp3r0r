//go:build linux
// +build linux

package util

import (
	"os"
	"strconv"
	"strings"
)

// GetMachineID retrieves the unique machine identifier
func GetMachineID() string {
	var id string
	// Try systemd machine-id
	idBytes, err := os.ReadFile("/etc/machine-id")
	if err == nil {
		id = strings.TrimSpace(string(idBytes))
	} else {
		// Try dbus machine-id
		idBytes, err = os.ReadFile("/var/lib/dbus/machine-id")
		if err == nil {
			id = strings.TrimSpace(string(idBytes))
		}
	}

	// Fallback to MAC-based ID if machine-id is missing (e.g. docker container, stripped OS)
	if id == "" {
		id = genShortID()
	}

	return id
}

// GetUptime returns system uptime
func GetUptime() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "Unknown"
	}
	parts := strings.Fields(string(data))
	if len(parts) == 0 {
		return "Unknown"
	}
	uptimeSecondsStr := parts[0]
	uptimeFloat, err := strconv.ParseFloat(uptimeSecondsStr, 64)
	if err != nil {
		return "Unknown"
	}
	return FormatUptime(int64(uptimeFloat))
}
