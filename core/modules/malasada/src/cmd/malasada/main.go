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
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
}

func run() error {
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
		return fmt.Errorf("expected one input file")
	}
	input := flag.Arg(0)
	if *output == "" {
		*output = input + ".bin"
	}
	so, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("read %s: %w", input, err)
	}
	fixed, err := materializeInitArray(so)
	if err != nil {
		return fmt.Errorf("materialize init array: %w", err)
	}
	tmp, err := os.CreateTemp("", "")
	if err != nil {
		return fmt.Errorf("create temp input: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(fixed); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp input: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp input: %w", err)
	}
	blob, err := malasada.ConvertSharedObject(tmpPath, *callExport, *compress)
	if err != nil {
		return fmt.Errorf("convert %s: %w", input, err)
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := os.WriteFile(*output, blob, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", *output, err)
	}
	fmt.Printf("[+] generated payload: %s (%d bytes)\n", *output, len(blob))
	return nil
}
