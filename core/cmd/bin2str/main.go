package main

import (
	"flag"
	"fmt"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/external_file"
)

func main() {
	file_path := flag.String("file", "", "File to compress")
	flag.Parse()
	if *file_path == "" {
		flag.Usage()
		os.Exit(1)
	}
	data, err := os.ReadFile(*file_path)
	if err != nil {
		logging.Fatalf("Failed to read file: %v", err)
	}
	compressedBin, err := external_file.Bin2String(data)
	if err != nil {
		logging.Fatalf("Failed to compress: %v", err)
	}
	fmt.Println(compressedBin)
}
