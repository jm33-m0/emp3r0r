//go:build windows
// +build windows

package util

import (
	"golang.org/x/sys/windows/registry"
)

// GetMachineID retrieves the unique machine identifier
func GetMachineID() string {
	var id string
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()
		guid, _, err := k.GetStringValue("MachineGuid")
		if err == nil {
			id = guid
		}
	}

	// Fallback to MAC-based ID if machine-id is missing (e.g. docker container, stripped OS)
	if id == "" {
		id = genShortID()
	}

	return id
}
