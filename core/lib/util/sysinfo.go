package util

import (
	"fmt"
	"log"
	"os"

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

// GetHostID unique identifier of the host
func GetHostID() (id string) {
	id = fmt.Sprintf("unknown_%d-agent", RandInt(0, 10000))
	name, err := os.Hostname()
	if err != nil {
		log.Printf("GetHostID: %v", err)
		return
	}
	id = fmt.Sprintf("%s_%d-agent", name, RandInt(0, 10000))
	productInfo, err := ghw.Product()
	if err != nil {
		log.Printf("GetHostID: %v", err)
		return
	}

	if productInfo.UUID != "unknown" {
		id = fmt.Sprintf("%s_%s-agent", name, productInfo.UUID)
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
