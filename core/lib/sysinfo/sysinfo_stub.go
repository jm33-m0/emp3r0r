//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

package sysinfo

import "fmt"

func GetOSInfo() (osinfo *OSInfo) {
	osinfo = &OSInfo{
		Vendor:       "Unknown",
		Name:         "Unknown",
		Version:      "Unknown",
		Release:      "Unknown",
		Architecture: "Unknown",
		Kernel:       "Unknown",
	}
	return osinfo
}

func CheckContainer() (product string) {
	return "None"
}

func CheckAccount(username string) (accountInfo map[string]string, err error) {
	return nil, fmt.Errorf("CheckAccount not implemented on this OS")
}

func crossPlatformHasRoot() bool {
	return false
}
