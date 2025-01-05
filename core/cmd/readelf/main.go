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

	headers, err := exe_utils.ParseELFHeaders(elf_data)
	if err != nil {
		panic(err)
	}

	// Print ELF headers
	if h, ok := headers.(*exe_utils.ELF64Header); ok {
		h.Print()
	}
}
