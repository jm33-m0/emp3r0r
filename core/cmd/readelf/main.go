//go:build linux
// +build linux

package main

import (
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/exe_utils"
)

func main() {
	elf_data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}

	h, err := exe_utils.ParseELFHeaders(elf_data)
	if err != nil {
		panic(err)
	}

	// Print ELF headers
	h.Print()
}
