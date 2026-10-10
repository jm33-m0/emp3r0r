//go:build linux

package util

import (
	"os"
	"strconv"
	"strings"
)

// GetUptime returns system uptime
func GetUptime() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "Unknown"
	}
	parts := strings.Fields(string(data))
	if len(parts) == 0 {
		return "Unknown"
	}
	uptimeSecondsStr := parts[0]
	uptimeFloat, err := strconv.ParseFloat(uptimeSecondsStr, 64)
	if err != nil {
		return "Unknown"
	}
	return FormatUptime(int64(uptimeFloat))
}
