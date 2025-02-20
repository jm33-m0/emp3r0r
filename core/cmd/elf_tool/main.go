//go:build linux
// +build linux

package main

import (
	"flag"
	"log"
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/exe_utils"
)

func main() {
	// Define command-line flags
	elfFilePath := flag.String("file", "", "Path to the ELF file")
	libName := flag.String("add-lib", "", "Name of the library to add to DT_NEEDED entries")
	flag.Parse()

	if *elfFilePath == "" {
		log.Fatal("ELF file path is required")
	}

	elf_data, err := os.ReadFile(*elfFilePath)
	if err != nil {
		log.Fatalf("Error reading ELF file: %v", err)
	}

	h, err := exe_utils.ParseELFHeaders(elf_data)
	if err != nil {
		log.Fatalf("Error parsing ELF headers: %v", err)
	}

	// Print ELF headers
	h.Print()

	// Add a specified library to the DT_NEEDED entries
	if *libName != "" {
		err = exe_utils.AddDTNeeded(*elfFilePath, *libName)
		if err != nil {
			log.Fatalf("Error adding library to DT_NEEDED entries: %v", err)
		}
		log.Printf("Added %s to DT_NEEDED entries", *libName)
	}
}
