package util

import (
	"fmt"

	"github.com/jaypipes/ghw"
)

func GetMemSize() int {
	memInfo, err := ghw.Memory()
	if err != nil {
		return -1
	}

	return int(memInfo.TotalUsableBytes) / 1024 / 1024
}

func GetCPUInfo() (info string) {
	cpuinfo, err := ghw.CPU()
	if err != nil {
		return
	}

	var cpus []string
loopProcessors:
	for _, cpu := range cpuinfo.Processors {
		percpu := fmt.Sprintf("%s %s", cpu.Vendor, cpu.Model)
		for _, c := range cpus {
			if c == percpu {
				continue loopProcessors
			}
		}
		cpus = append(cpus, percpu)
	}

	info = cpuinfo.String()

	for _, c := range cpus {
		info += ", " + c
	}

	return
}

// CheckProduct check machine details
func CheckProduct() (product string) {
	product = "unknown_product"
	productInfo, err := ghw.Product()
	if err != nil {
		return
	}
	product = fmt.Sprintf("%s (%s) by %s",
		productInfo.Name,
		productInfo.Version,
		productInfo.Vendor)

	return
}
