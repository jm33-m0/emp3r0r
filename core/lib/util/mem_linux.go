//go:build linux
// +build linux

package util

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// ReadMemoryRegion reads a specified memory region from the given process handle
// hProcess is the file descriptor of open file /proc/pid/mem, or 0 for current process
// address is the starting address of the memory region
// size is the size of the memory region to read
func ReadMemoryRegion(hProcess uintptr, address, size uintptr) (data []byte, err error) {
	mem := os.NewFile(hProcess, "mem")
	if hProcess == 0 {
		mem, err = os.Open(fmt.Sprintf("/proc/%d/mem", os.Getpid()))
		if err != nil {
			return nil, fmt.Errorf("failed to open /proc/%d/mem: %v", os.Getpid(), err)
		}
		defer mem.Close()
	}
	read_buf := make([]byte, size)
	n, err := mem.ReadAt(read_buf, int64(address))
	if err != nil || n <= 0 {
		return nil, fmt.Errorf("failed to read memory region: %v", err)
	}
	return read_buf, nil
}

// crossPlatformDumpSelfMem dumps everything (readable) from the self process
// It will dump libraries as well, if any
// This function is Linux only
func crossPlatformDumpSelfMem() (memdata map[int64][]byte, err error) {
	maps_file := fmt.Sprintf("/proc/%d/maps", os.Getpid())
	mem_file := fmt.Sprintf("/proc/%d/mem", os.Getpid())
	memdata = make(map[int64][]byte)

	// open memory
	mem, err := os.Open(mem_file)
	defer mem.Close()
	if err != nil {
		return nil, fmt.Errorf("open %s: %v", mem_file, err)
	}

	// parse maps
	maps, err := os.Open(maps_file)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(maps)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineSplit := strings.Fields(line)
		if len(lineSplit) == 1 {
			log.Printf("%s: failed to parse", line)
			continue
		}
		if !strings.HasPrefix(lineSplit[1], "r") {
			// if not readable
			log.Printf("%s: not readable", line)
			continue
		}

		// parse map line
		start_end := strings.Split(lineSplit[0], "-")
		if len(start_end) == 1 {
			log.Printf("%s: failed to parse", line)
			continue
		}
		start, err := strconv.ParseInt(start_end[0], 16, 64)
		if err != nil {
			log.Printf("%s: failed to parse start", line)
		}
		end, err := strconv.ParseInt(start_end[1], 16, 64)
		if err != nil {
			log.Printf("%s: failed to parse end", line)
		}

		// read memory region
		read_buf, err := ReadMemoryRegion(0, uintptr(start), uintptr(end-start))
		if err != nil {
			log.Printf("%s: %v", line, err)
			continue
		}
		log.Printf("%s: read %d bytes", line, len(read_buf))
		memdata[start] = read_buf
	}

	return
}

const (
	mfdCloexec     = 0x0001
	memfdCreateX64 = 319
	fork           = 57
)

// MemFDWrite creates a memfd and writes data to it
// It returns the file descriptor of the created memfd
func MemFDWrite(data []byte) int {
	mem_name := ""
	fd, _, errno := syscall.Syscall(memfdCreateX64, uintptr(unsafe.Pointer(&mem_name)), uintptr(0), 0)
	if errno < 0 {
		log.Printf("MemFDWrite: %v", errno)
		return -1
	}
	_, err := syscall.Write(int(fd), data)
	if err != nil {
		log.Printf("MemFDWrite: %v", err)
		return -1
	}
	return int(fd)
}
