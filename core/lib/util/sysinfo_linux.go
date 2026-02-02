//go:build linux
// +build linux

package util

import (
	"os"
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
