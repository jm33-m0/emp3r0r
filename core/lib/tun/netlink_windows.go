//go:build windows
// +build windows

package tun

import (
	"fmt"
	"os/exec"
	"strings"
)

func crossPlatformIPNeigh() (table []string) {
	data, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return nil
	}

	skipNext := false
	for _, line := range strings.Split(string(data), "\n") {
		// skip empty lines
		if len(line) <= 0 {
			continue
		}
		// skip Interface: lines
		if line[0] != ' ' {
			skipNext = true
			continue
		}
		// skip column headers
		if skipNext {
			skipNext = false
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		ip := fields[0]
		// Normalize MAC address to colon-separated format
		mac := strings.Replace(fields[1], "-", ":", -1)

		// append
		table = append(table, fmt.Sprintf("%s (%s), ", ip, mac))
	}

	return table
}

func crossPlatformIPr() (routes []string) {
	return
}
