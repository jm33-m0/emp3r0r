// Command malasada wraps a Linux ELF shared object in a position-independent
// stage0 blob. The converter source lives in this module so the detection loop
// can edit and rebuild it like any other shellcode producer.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"malasada"
)

func main() {
	var (
		callExport = flag.String("call-export", malasada.DefaultCallExport, "exported symbol called by the stage0 stub")
		output     = flag.String("o", "", "output raw PIC file (default: <input>.bin)")
		compress   = flag.Bool("compress", false, "aPLib-compress the payload before embedding")
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: malasada [options] <input.so>\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	input := flag.Arg(0)
	if *output == "" {
		*output = input + ".bin"
	}
	so, err := os.ReadFile(input)
	if err != nil {
		fail("read %s: %v", input, err)
	}
	fixed, err := materializeInitArray(so)
	if err != nil {
		fail("materialize init array: %v", err)
	}
	tmp, err := os.CreateTemp("", "")
	if err != nil {
		fail("create temp input: %v", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(fixed); err != nil {
		tmp.Close()
		fail("write temp input: %v", err)
	}
	if err := tmp.Close(); err != nil {
		fail("close temp input: %v", err)
	}
	blob, err := malasada.ConvertSharedObject(tmpPath, *callExport, *compress)
	if err != nil {
		fail("convert %s: %v", input, err)
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		fail("create output directory: %v", err)
	}
	if err := os.WriteFile(*output, blob, 0o600); err != nil {
		fail("write %s: %v", *output, err)
	}
	fmt.Printf("[+] generated payload: %s (%d bytes)\n", *output, len(blob))
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[-] "+format+"\n", args...)
	os.Exit(1)
}
