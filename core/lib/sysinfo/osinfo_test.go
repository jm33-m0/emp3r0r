package sysinfo

import (
	"runtime"
	"testing"
)

func TestGetOSInfo(t *testing.T) {
	info := GetOSInfo()
	if info == nil {
		t.Fatal("GetOSInfo returned nil")
	}

	// Basic validation
	if info.Architecture == "" {
		t.Error("OSInfo.Architecture is empty")
	}

	// On Linux, we expect some fields to be populated if /etc/os-release exists
	if runtime.GOOS == "linux" {
		// We can't guarantee /etc/os-release exists in the test environment,
		// but if it does, Name/Vendor/Version should likely be set.
		// At least Architecture should be set by the .so check or fallback.
	}
}

func TestHasRoot(t *testing.T) {
	// Just ensure it doesn't panic and returns a boolean
	_ = HasRoot()
}
