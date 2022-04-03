package util

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strings"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
)

// ExtractData extract embedded data from args[0] or process memory
func ExtractData() (data []byte, err error) {
	data, err = DigEmbeddedDataFromExe()
	if err != nil {
		e := err
		log.Printf("Extract ELF from args[0]: %v", err)
		data, err = DigEmbededDataFromMem()
		if err != nil {
			err = fmt.Errorf("Extract data from args[0]: %v. from memory: %v", e, err)
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
	exe_data, err = ioutil.ReadFile(process_exe_file)

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
	sep := []byte(strings.Repeat(emp3r0r_data.MagicString, 3))

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
			log.Printf("memory region %d (%d bytes): %v", n, len(mem_region), err)
			continue
		}
		break
	}
	if len(data) <= 0 {
		return nil, fmt.Errorf("No config data found in memory")
	}

	return
}

// DumpSelfMem dump all mapped memory regions of current process
func DumpSelfMem() ([][]byte, error) {
	return crossPlatformDumpSelfMem()
}
