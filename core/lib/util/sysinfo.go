package util

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"strings"

	"github.com/jaypipes/ghw"
)

func GetMemSize() int {
	memInfo, err := ghw.Memory(ghw.WithDisableWarnings())
	if err != nil {
		log.Printf("GetMemSize error: %v", err)
		return -1
	}

	return int(float32(memInfo.TotalUsableBytes) / 1024 / 1024)
}

func GetGPUInfo() (info string) {
	gpuinfo, err := ghw.GPU(ghw.WithDisableWarnings())
	if err != nil {
		return "no_gpu"
	}

	for _, card := range gpuinfo.GraphicsCards {
		info += card.String() + "\n"
	}

	info = strings.TrimSpace(info)
	return
}

func GetCPUInfo() (info string) {
	cpuinfo, err := ghw.CPU(ghw.WithDisableWarnings())
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

func GetKernelVersion() (uname string) {
	release, err := ioutil.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		release = []byte("unknown_release")
	}
	version, err := ioutil.ReadFile("/proc/sys/kernel/version")
	if err != nil {
		version = []byte("unknown_version")
	}

	return fmt.Sprintf("%s Linux %s", release, version)
}

// Golang code to get MAC address for purposes of generating a unique id. Returns a uint64.
// Skips virtual MAC addresses (Locally Administered Addresses).
func macUint64() uint64 {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("macUint64: %v", err)
		return uint64(0)
	}

	for _, i := range interfaces {
		if i.Flags&net.FlagUp != 0 && bytes.Compare(i.HardwareAddr, nil) != 0 {

			// Skip locally administered addresses
			if i.HardwareAddr[0]&2 == 2 {
				continue
			}

			var mac uint64
			for j, b := range i.HardwareAddr {
				if j >= 8 {
					break
				}
				mac <<= 8
				mac += uint64(b)
			}

			return mac
		}
	}

	return uint64(0)
}

// generate a static short identifier for the current host
func genShortID() (id string) {
	return fmt.Sprintf("%x", macUint64())
}

// GetHostID unique identifier of the host
func GetHostID(fallbackUUID string) (id string) {
	shortID := genShortID()
	id = fmt.Sprintf("unknown_%s-agent", shortID)
	name, err := os.Hostname()
	if err != nil {
		log.Printf("GetHostID: %v", err)
		return
	}
	name = fmt.Sprintf("%s\\%s", name, GetUsername())
	id = fmt.Sprintf("%s_%s-agent-%s", name, shortID, fallbackUUID)
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
	productInfo, err := ghw.Product(ghw.WithDisableWarnings())
	if err != nil {
		return
	}
	product = fmt.Sprintf("%s (%s) by %s",
		productInfo.Name,
		productInfo.Version,
		productInfo.Vendor)

	return
}
