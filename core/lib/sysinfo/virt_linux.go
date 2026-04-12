//go:build linux
// +build linux

package sysinfo

import (
	"os"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// CheckContainer are we in a container? what container is it?
func CheckContainer() (product string) {
	product = "None"
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return
	}
	lines := strings.SplitSeq(string(data), "\n")
	for line := range lines {
		if strings.Contains(line, "freezer") {
			fields := strings.Split(line, ":")
			if len(fields) > 2 &&
				fields[len(fields)-1] != "/" {
				product = strings.Split(fields[2], "/")[1]
				logging.Infof("Inside a container: %s", product)
				return
			}
		}
	}

	return
}
