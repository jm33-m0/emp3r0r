package util

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"runtime"
	"strings"

	"github.com/google/uuid"
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
func GetHostID(info *ghw.ProductInfo, fallbackUUID string) (id string) {
	// check if info is nil
	if info == nil {
		info = &ghw.ProductInfo{}
		info.UUID = fallbackUUID
		info.SerialNumber = fallbackUUID
	}

	shortID := genShortID()
	id = fmt.Sprintf("unknown_hostname_%s-agent", shortID)
	name, err := os.Hostname()
	if err != nil {
		log.Printf("GetHostID: %v", err)
		return
	}
	name = fmt.Sprintf("%s\\%s", name, GetUsername()) // hostname\\username
	id = fmt.Sprintf("%s_%s-agent", name, shortID)
	fallback := false
	product_uuid, err := uuid.Parse(info.UUID)
	if err != nil {
		log.Printf("GetHostID: %v", err)
		fallback = true
	}
	if product_uuid.ID() == 0 {
		// ghw might return a zero UUID
		// which we don't need
		fallback = true
	}
	id = fmt.Sprintf("%s_%s-agent-%s", name, shortID, fallbackUUID)

	if !fallback {
		id = fmt.Sprintf("%s_%s-agent-%s", name, shortID, info.UUID)
	}
	return
}

// ScanPATH scan $PATH and return a list of executables, for autocomplete
func ScanPATH() (exes []string) {
	path_str := os.Getenv("PATH")
	sep := ":"
	if runtime.GOOS == "windows" {
		sep = ";"
	}

	paths := strings.Split(path_str, sep)
	if len(paths) < 1 {
		exes = []string{""}
		log.Printf("Empty PATH: %s", path_str)
		return
	}

	// scan paths
	for _, path := range paths {
		files, err := os.ReadDir(path)
		if err != nil {
			continue
		}
		for _, f := range files {
			exes = append(exes, f.Name())
		}
	}
	log.Printf("Found %d executables from PATH (%s)", len(exes), path_str)
	return
}

func GetProductInfo() (product *ghw.ProductInfo, err error) {
	product, err = ghw.Product(ghw.WithDisableWarnings())
	if err != nil {
		log.Printf("GetProductInfo: %v", err)
		return
	}

	return
}

// CheckProduct check machine details
func CheckProduct(info *ghw.ProductInfo) (product string) {
	if info == nil {
		return "unknown_product"
	}

	product = fmt.Sprintf("%s (%s) by %s",
		info.Name,
		info.Version,
		info.Vendor)

	return
}
