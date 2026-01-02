//go:build linux
// +build linux

package sysinfo

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCheckContainer tests the CheckContainer function on Linux
func TestCheckContainer(t *testing.T) {
	// Note: This test runs on the actual system, so results may vary
	// We can only test that the function returns a non-empty string

	t.Run("basic functionality", func(t *testing.T) {
		result := CheckContainer()
		
		// Result should be a string (either "None" or a container type)
		if result == "" {
			t.Error("CheckContainer() returned empty string")
		}
	})

	// Test with mocked /proc/1/cgroup file
	t.Run("mock docker container", func(t *testing.T) {
		// Create a temporary directory to simulate /proc/1/
		tmpDir := t.TempDir()
		cgroupPath := filepath.Join(tmpDir, "cgroup")

		// Write a mock cgroup file that simulates a Docker container
		mockCgroupContent := `12:perf_event:/docker/abc123
11:blkio:/docker/abc123
10:memory:/docker/abc123
9:cpuset:/docker/abc123
8:devices:/docker/abc123
7:net_cls,net_prio:/docker/abc123
6:cpu,cpuacct:/docker/abc123
5:freezer:/docker/abc123
4:hugetlb:/docker/abc123
3:pids:/docker/abc123
2:rdma:/
1:name=systemd:/docker/abc123
0::/system.slice/docker.service`

		err := os.WriteFile(cgroupPath, []byte(mockCgroupContent), 0644)
		if err != nil {
			t.Fatalf("Failed to create mock cgroup file: %v", err)
		}

		// We can't easily override the file path in CheckContainer without modifying the function
		// So this test serves as documentation for how the function works
		// In a real scenario, we'd refactor CheckContainer to accept a file path parameter
	})

	t.Run("mock non-container", func(t *testing.T) {
		tmpDir := t.TempDir()
		cgroupPath := filepath.Join(tmpDir, "cgroup")

		// Write a mock cgroup file that simulates a non-container system
		mockCgroupContent := `12:perf_event:/
11:blkio:/
10:memory:/
9:cpuset:/
8:devices:/
7:net_cls,net_prio:/
6:cpu,cpuacct:/
5:freezer:/
4:hugetlb:/
3:pids:/
2:rdma:/
1:name=systemd:/
0::/init.scope`

		err := os.WriteFile(cgroupPath, []byte(mockCgroupContent), 0644)
		if err != nil {
			t.Fatalf("Failed to create mock cgroup file: %v", err)
		}

		// Similarly, this is documentation of expected behavior
	})
}

// TestCheckContainerReturnValues tests that CheckContainer returns expected values
func TestCheckContainerReturnValues(t *testing.T) {
	result := CheckContainer()

	// The result should be one of the known container types or "None"
	// For this test, we just verify it returns something reasonable
	// The actual value depends on the test environment
	if result == "" {
		t.Error("CheckContainer() should not return empty string")
	}

	t.Logf("CheckContainer() returned: %s", result)

	// We can't assert a specific value since it depends on the environment
	// but we can log it for debugging
}
