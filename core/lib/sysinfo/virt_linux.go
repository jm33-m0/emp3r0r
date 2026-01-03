//go:build linux
// +build linux

package sysinfo

import (
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"os"
	"strings"
)

// CheckContainer are we in a container? what container is it?
func CheckContainer() (product string) {
	product = "None"
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.Contains(line, "freezer") {
			fields := strings.Split(line, ":")
			if len(fields) > 1 &&
				fields[len(fields)-1] != "/" {
				product = strings.Split(fields[2], "/")[1]
				logging.Println("Inside a container: ", product)
				return
			}
		}
	}

	return
}
