//go:build linux
// +build linux

package sysinfo

import (
	"os"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func detectContainerFromCgroup(data string) string {
	lower := strings.ToLower(data)

	// Fast-path keyword detection for common runtimes.
	type containerToken struct {
		token string
		name  string
	}
	tokens := []containerToken{
		{token: "kubepods", name: "kubernetes"},
		{token: "containerd", name: "containerd"},
		{token: "docker", name: "docker"},
		{token: "libpod", name: "podman"},
		{token: "podman", name: "podman"},
		{token: "cri-o", name: "cri-o"},
		{token: "crio", name: "cri-o"},
		{token: "lxc", name: "lxc"},
	}
	for _, t := range tokens {
		if strings.Contains(lower, t.token) {
			return t.name
		}
	}

	// Legacy cgroup-v1 freezer parser fallback.
	for _, line := range strings.Split(data, "\n") {
		if !strings.Contains(line, "freezer") {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) <= 2 || fields[len(fields)-1] == "/" {
			continue
		}

		segments := strings.Split(strings.Trim(fields[2], "/"), "/")
		if len(segments) > 0 && segments[0] != "" {
			return segments[0]
		}
	}

	return ""
}

// CheckContainer are we in a container? what container is it?
func CheckContainer() (product string) {
	product = "None"

	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker"
	}

	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return "podman"
	}

	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return product
	}

	if detected := detectContainerFromCgroup(string(data)); detected != "" {
		logging.Infof("Inside a container: %s", detected)
		return detected
	}

	return product
}
