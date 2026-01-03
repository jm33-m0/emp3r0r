//go:build linux
// +build linux

package main

import (
	"flag"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/exeutil"
)

func main() {
	// Define command-line flags
	elfFilePath := flag.String("file", "", "Path to the ELF file")
	libName := flag.String("add-lib", "", "Name of the library to add to DT_NEEDED entries")
	flag.Parse()

	if *elfFilePath == "" {
		logging.Fatal("ELF file path is required")
	}

	elf_data, err := os.ReadFile(*elfFilePath)
	if err != nil {
		logging.Fatalf("Error reading ELF file: %v", err)
	}

	h, err := exeutil.ParseELFHeaders(elf_data)
	if err != nil {
		logging.Fatalf("Error parsing ELF headers: %v", err)
	}

	// Print ELF headers
	h.Print()

	// Add a specified library to the DT_NEEDED entries
	if *libName != "" {
		err = exeutil.AddDTNeeded(*elfFilePath, *libName)
		if err != nil {
			logging.Fatalf("Error adding library to DT_NEEDED entries: %v", err)
		}
		logging.Printf("Added %s to DT_NEEDED entries", *libName)
	}
}
