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
func DigEmbeddedDataFromArg0() (data []byte, err error) {
	wholeStub, err := ioutil.ReadFile(os.Args[0])
	if err != nil {
		return
	}
	sep := []byte(strings.Repeat(emp3r0r_data.MagicString, 3))

	// locate the JSON file
	split := bytes.Split(wholeStub, sep)
	if len(split) < 2 {
		return nil, fmt.Errorf("No magic string found in file %s", os.Args[0])
	}
	data = split[1]
	if len(data) <= 0 {
		return nil, fmt.Errorf("No config data found in file %s", os.Args[0])
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
		sep        = []byte(strings.Repeat(emp3r0r_data.MagicString, 3))
	)
	for _, mem_region = range mem_regions {
		// locate the JSON file
		split := bytes.Split(mem_region, sep)
		if len(split) < 2 {
			continue
		}
		data = split[1]
		log.Printf("len(split) = %d, split[0] = %s... (%d bytes), split[1] = %s... (%d bytes)",
			len(split), split[0], len(split[0][:30]), split[1][:30], len(split[1]))
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
