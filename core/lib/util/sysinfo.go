package util

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"strconv"

	"github.com/google/uuid"
	"github.com/jaypipes/ghw"
)

func GetMemSize() int {
	memInfo, err := ghw.Memory()
	if err != nil {
		log.Printf("GetMemSize error: %v", err)
		return -1
	}

	return int(float32(memInfo.TotalUsableBytes) / 1024 / 1024)
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

func GetUsername() string {
	// user account info
	u, err := user.Current()
	if err != nil {
		log.Printf("GetUsername: %v", err)
		return "unknown_user"
	}
	return u.Username
}

// GetHostID unique identifier of the host
func GetHostID() (id string) {
	shortID := strconv.Itoa(RandInt(10, 10240))
	id = fmt.Sprintf("unknown_%s-agent", shortID)
	name, err := os.Hostname()
	if err != nil {
		log.Printf("GetHostID: %v", err)
		return
	}
	name = fmt.Sprintf("%s\\%s", name, GetUsername())
	uuidstr := uuid.New().String()
	id = fmt.Sprintf("%s_%s-agent-%s", name, shortID, uuidstr)
	productInfo, err := ghw.Product()
	if err != nil {
		log.Printf("GetHostID: %v", err)
		return
	}

	if productInfo.UUID != "unknown" {
		id = fmt.Sprintf("%s_%s-agent-%s", name, shortID, productInfo.UUID)
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
