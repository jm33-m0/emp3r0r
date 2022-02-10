//go:build linux
// +build linux

package agent

import (
	"bufio"
	"debug/elf"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

// GetSymFromLibc: Get pointer to a libc function
// that is currently loaded in target process, ASLR-proof
func GetSymFromLibc(pid int, sym string) (addr int64) {
	libc_path, base, offset := GetLibc(pid)
	if base == 0 {
		return
	}
	elf_file, err := elf.Open(libc_path)
	if err != nil {
		log.Printf("ELF open: %v", err)
		return
	}
	defer elf_file.Close()
	syms, err := elf_file.DynamicSymbols()
	if err != nil {
		log.Printf("ELF symbols: %v", err)
		return
	}
	for _, s := range syms {
		if strings.Contains(s.Name, sym) {
			addr = base + int64(s.Value) - offset
			break
		}
	}
	log.Printf("Address of %s is 0x%x", sym, addr)

	return
}

// GetLibc get base address, ASLR offset value, and path of libc
// by parsing /proc/pid/maps
func GetLibc(pid int) (path string, addr, offset int64) {
	map_path := fmt.Sprintf("/proc/%d/maps", pid)

	f, err := os.Open(map_path)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "libc-") ||
			!strings.Contains(line, " r-xp ") {
			continue
		}
		fields := strings.Fields(line)
		addr, _ = strconv.ParseInt(strings.Split(line, "-")[0], 16, 64)
		offset, _ = strconv.ParseInt(fields[2], 16, 64)

		path = fields[len(fields)-1]
		log.Printf("libc base addr is 0x%x, offset is 0x%x, path is %s",
			addr, offset, path)
		break
	}
	return
}
