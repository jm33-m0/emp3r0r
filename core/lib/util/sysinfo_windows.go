//go:build windows

package util

import (
	"syscall"
)

// GetUptime returns system uptime
func GetUptime() string {
	// Let's use GetTickCount64 from kernel32
	k32 := syscall.NewLazyDLL("kernel32.dll")
	getTickCount64 := k32.NewProc("GetTickCount64")
	ret, _, _ := getTickCount64.Call()
	millis := int64(ret)
	return FormatUptime(millis / 1000)
}
