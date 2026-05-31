//go:build linux

package sysinfo

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func GetHardwareInfo() string {
	var vendor, prodName, prodVersion string
	if b, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		vendor = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		prodName = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/sys/class/dmi/id/product_version"); err == nil {
		prodVersion = strings.TrimSpace(string(b))
	}
	info := fmt.Sprintf("%s (%s) by %s", prodName, prodVersion, vendor)
	if info == " () by " {
		return "Unknown Linux Device"
	}
	return info
}

func GetCPUInfo() string {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "unknown_cpu"
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "model name") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return "unknown_cpu"
}

func GetGPUInfo() string {
	return "unknown_gpu"
}

func GetMemSize() int {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return -1
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseInt(fields[1], 10, 64)
				return int(kb / 1024)
			}
		}
	}
	return -1
}
