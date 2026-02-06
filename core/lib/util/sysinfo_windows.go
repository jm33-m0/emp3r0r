//go:build windows
// +build windows

package util

import (
	"syscall"

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

// GetUptime returns system uptime
func GetUptime() string {
	// Let's use GetTickCount64 from kernel32
	k32 := syscall.NewLazyDLL("kernel32.dll")
	getTickCount64 := k32.NewProc("GetTickCount64")
	ret, _, _ := getTickCount64.Call()
	millis := int64(ret)
	return FormatUptime(millis / 1000)
}
