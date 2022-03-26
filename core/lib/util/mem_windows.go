//go:build windows
// +build windows

package util

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
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
