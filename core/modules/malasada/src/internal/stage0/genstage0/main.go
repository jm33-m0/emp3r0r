package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	var (
		zigPath string
		outDir  string
		arch    string
	)
	flag.StringVar(&zigPath, "zig", "", "Path to zig binary (default: from PATH)")
	flag.StringVar(&outDir, "out", "", "Output directory (required)")
	flag.StringVar(&arch, "arch", "", "Target architecture: 386, amd64, or arm64 (default: all)")
	flag.Parse()

	if outDir == "" {
		fatalf("missing required flag: -out")
	}

	zig := zigPath
	if zig == "" {
		p, err := exec.LookPath("zig")
		if err != nil {
			fatalf("zig not found in PATH")
		}
		zig = p
	}

	stage0C := filepath.Join(outDir, "stage0.c")
	linkerLD := filepath.Join(outDir, "linker.ld")

	// Expect the stage0 sources in outDir (repo layout: internal/stage0/*).
	// This keeps paths simple when invoked via `go generate` from repo root.
	if _, err := os.Stat(stage0C); err != nil {
		fatalf("missing %s: %v", stage0C, err)
	}
	if _, err := os.Stat(linkerLD); err != nil {
		fatalf("missing %s: %v", linkerLD, err)
	}

	stage0Debug := os.Getenv("MALASADA_STAGE0_DEBUG") != ""

	tmpDir, err := os.MkdirTemp("", "malasada-generate-stage0-*")
	if err != nil {
		fatalf("mkdtemp: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	type target struct {
		zigTarget string
		outFile   string
	}
	targets := []target{
		{zigTarget: "x86-linux-gnu", outFile: "stage0_linux_386.bin"},
		{zigTarget: "x86_64-linux-gnu", outFile: "stage0_linux_amd64.bin"},
		{zigTarget: "aarch64-linux-gnu", outFile: "stage0_linux_arm64.bin"},
	}
	if arch != "" {
		var selected []target
		for _, t := range targets {
			if strings.HasSuffix(t.outFile, "_"+arch+".bin") {
				selected = append(selected, t)
			}
		}
		if len(selected) == 0 {
			fatalf("unsupported architecture %q", arch)
		}
		targets = selected
	}

	for _, t := range targets {
		elfOut := filepath.Join(tmpDir, "stage0-"+t.zigTarget+".elf")
		binOut := filepath.Join(tmpDir, "stage0-"+t.zigTarget+".bin")

		args := []string{
			"cc",
			"-target", t.zigTarget,
		}
		// Stage0 is executed as a raw .text blob (shellcode-like). It must be
		// position-independent so symbol addressing works when the runner mmaps
		// it at an arbitrary address.
		//
		// x86 (32-bit) and x86_64 need explicit PIE flags to avoid absolute
		// symbol immediates.
		// aarch64 codegen is already PC-relative for our usage, and forcing PIE
		// here can introduce relocations we do not apply to the raw blob.
		if t.zigTarget == "x86_64-linux-gnu" || t.zigTarget == "x86-linux-gnu" {
			args = append(args, "-fpie", "-pie")
		}
		if stage0Debug {
			args = append(args, "-DMALASADA_STAGE0_DEBUG=1")
		}
		args = append(args,
			"-ffreestanding", "-nostdlib",
			"-fno-sanitize=all",
			"-fno-stack-protector",
			"-fno-asynchronous-unwind-tables",
			"-fno-unwind-tables",
			"-ffunction-sections", "-fdata-sections",
			"-Wl,--gc-sections",
			"-Wl,--build-id=none",
			"-Wl,-T,"+linkerLD,
			"-Oz",
			"-o", elfOut,
			stage0C,
		)
		cmd := exec.Command(zig, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fatalf("zig cc (%s): %v", t.zigTarget, err)
		}

		cmd = exec.Command(zig, "objcopy",
			"-O", "binary",
			"-j", ".text",
			elfOut,
			binOut,
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fatalf("zig objcopy (%s): %v", t.zigTarget, err)
		}

		stage0, err := os.ReadFile(binOut)
		if err != nil {
			fatalf("read stage0 bin (%s): %v", t.zigTarget, err)
		}
		if err := verifyMSDAHeaderAtEnd(stage0); err != nil {
			fatalf("verify stage0 bin (%s): %v", t.zigTarget, err)
		}

		outPath := filepath.Join(outDir, t.outFile)
		if err := os.WriteFile(outPath, stage0, 0o644); err != nil {
			fatalf("write %s: %v", outPath, err)
		}
	}
}

var msdaMagic = []byte("MALASADA")

func verifyMSDAHeaderAtEnd(stage0 []byte) error {
	const headerSize = 8 + 4 + 4 + 8
	if len(stage0) < headerSize {
		return fmt.Errorf("stage0 too small")
	}
	off := bytes.LastIndex(stage0, msdaMagic)
	if off < 0 {
		return fmt.Errorf("missing msda header")
	}
	if off+headerSize != len(stage0) {
		return fmt.Errorf("msda header is not at end (off=%d len=%d)", off, len(stage0))
	}
	return nil
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
