//go:build linux
// +build linux

package sysinfo

import (
	"os"
	"testing"
)

func TestDetectContainerFromCgroup(t *testing.T) {
	tests := []struct {
		name    string
		cgroup  string
		expect  string
	}{
		{
			name: "docker v1 style",
			cgroup: `12:perf_event:/docker/abc123
11:blkio:/docker/abc123
5:freezer:/docker/abc123
0::/system.slice/docker.service`,
			expect: "docker",
		},
		{
			name: "containerd/kubernetes",
			cgroup: `0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234.slice/containerd://abcdef`,
			expect: "kubernetes",
		},
		{
			name: "podman",
			cgroup: `0::/user.slice/user-1000.slice/user@1000.service/app.slice/libpod-123456.scope`,
			expect: "podman",
		},
		{
			name: "none",
			cgroup: `12:perf_event:/
11:blkio:/
5:freezer:/
0::/init.scope`,
			expect: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := detectContainerFromCgroup(tc.cgroup); got != tc.expect {
				t.Fatalf("detectContainerFromCgroup() = %q, want %q", got, tc.expect)
			}
		})
	}
}

// TestCheckContainer_InsideDockerProbe is executed from an external docker-based test.
func TestCheckContainer_InsideDockerProbe(t *testing.T) {
	if os.Getenv("EMP3R0R_IN_DOCKER_PROBE") != "1" {
		t.Skip("only runs inside docker probe")
	}

	result := CheckContainer()
	if result == "" || result == "None" {
		t.Fatalf("CheckContainer() = %q inside container, expected non-empty container runtime", result)
	}
}
