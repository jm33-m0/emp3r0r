package agent

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

var RuntimeConfig = &emp3r0r_data.Config{}

func ApplyRuntimeConfig() (err error) {
	encJsonData, err := DigEmbeddedDataFromArg0()
	if err != nil {
		e := err
		log.Printf("readConfigFromFile: %v", err)
		encJsonData, err = DigEmbededDataFromMem()
		if err != nil {
			return fmt.Errorf("readConfigFromFile: %v. readConfigFromMem: %v", e, err)
		}
	}

	// decrypt attached JSON file
	key := tun.GenAESKey(emp3r0r_data.MagicString)
	decJsonData := tun.AESDecryptRaw(key, encJsonData)
	if decJsonData == nil {
		err = fmt.Errorf("Decrypt JSON with key %s failed", key)
		return
	}

	// parse JSON
	err = emp3r0r_data.ReadJSONConfig(decJsonData, RuntimeConfig)
	if err != nil {
		short_view := decJsonData
		if len(decJsonData) > 100 {
			short_view = decJsonData[:100]
		}
		return fmt.Errorf("parsing %d bytes of JSON data (%s...): %v", len(decJsonData), short_view, err)
	}

	// CA
	tun.CACrt = []byte(RuntimeConfig.CA)
	return
}

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

// DumpSelfMem dump everything (readable) from self process
// will dump libraries as well, if any
// Linux only
func DumpSelfMem() (memdata [][]byte, err error) {
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
