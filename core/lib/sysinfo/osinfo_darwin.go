//go:build darwin
// +build darwin

package sysinfo

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
