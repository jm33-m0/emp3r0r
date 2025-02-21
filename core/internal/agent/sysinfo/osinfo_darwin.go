//go:build darwin
// +build darwin

package sysinfo

import "os"

func genOSRelease() {
	// Dummy implementation for Darwin
}

func GetOSInfo() *OSInfo {
	// Dummy implementation for Darwin: returning an empty OSInfo
	return &OSInfo{
		Architecture: "unknown",
		Vendor:       "Darwin",
		Name:         "Darwin",
		Version:      "dummy",
		Release:      "dummy",
		Kernel:       GetKernelVersion(),
	}
}

func GetKernelVersion() string {
	// Dummy implementation returning a static string.
	return "darwin_dummy"
}

func slurpFile(path string) string {
	// Dummy implementation: return an empty string.
	return ""
}

func spewFile(path string, data string, perm os.FileMode) {
	// Dummy implementation: do nothing.
}
