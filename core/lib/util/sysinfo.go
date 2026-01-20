package util

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jaypipes/ghw"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func GetMemSize() int {
	memInfo, err := ghw.Memory(ghw.WithDisableWarnings())
	if err != nil {
		logging.Debugf("GetMemSize error: %v", err)
		return -1
	}

	return int(float32(memInfo.TotalUsableBytes) / 1024 / 1024)
}

// GetMemAvailable returns available memory in bytes
// It tries to read /proc/meminfo on Linux
func GetMemAvailable() int64 {
	if runtime.GOOS == "linux" {
		f, err := os.Open("/proc/meminfo")
		if err != nil {
			return -1
		}
		defer f.Close()

		s := bufio.NewScanner(f)
		for s.Scan() {
			line := s.Text()
			// Look for MemAvailable
			if strings.HasPrefix(line, "MemAvailable:") {
				parts := strings.Fields(line)
				if len(parts) < 2 {
					return -1
				}
				kb, err := strconv.ParseInt(parts[1], 10, 64)
				if err != nil {
					return -1
				}
				return kb * 1024
			}
		}
	}
	// Fallback or other OS
	return -1
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
		logging.Debugf("GetUsername: %v", err)
		return "unknown_user"
	}
	return u.Username
}

// Golang code to get MAC address for purposes of generating a unique id. Returns a uint64.
// Skips virtual MAC addresses (Locally Administered Addresses).
func macUint64() uint64 {
	interfaces, err := net.Interfaces()
	if err != nil {
		logging.Debugf("macUint64: %v", err)
		return uint64(0)
	}

	for _, i := range interfaces {
		if i.Flags&net.FlagUp != 0 && bytes.Equal(i.HardwareAddr, nil) {

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
		logging.Debugf("GetHostID: %v", err)
		return
	}
	name = fmt.Sprintf("%s\\%s", name, GetUsername()) // hostname\\username
	fallback := false
	product_uuid, err := uuid.Parse(info.UUID)
	if err != nil {
		logging.Debugf("GetHostID: %v", err)
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
		logging.Debugf("Empty PATH: %s", path_str)
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
	logging.Debugf("Found %d executables from PATH (%s)", len(exes), path_str)
	return
}

func GetProductInfo() (product *ghw.ProductInfo, err error) {
	product, err = ghw.Product(ghw.WithDisableWarnings())
	if err != nil {
		logging.Debugf("GetProductInfo: %v", err)
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
