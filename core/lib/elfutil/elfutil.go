// Package elfutil provides small, dependency-free helpers for inspecting ELF
// images held in memory.
//
// It exists so an eBPF uprobe can be attached to a byte pattern found in a
// target's executable code without ptrace: a uprobe's offset is a file offset
// within the probed binary, so scanning the ELF image's executable PT_LOAD
// segments yields the exact value the kernel needs. Callers read the image
// through the agent's I/O layer (util.ReadFileAgent); this package never opens
// a file itself, so it stays usable with memfs and never bypasses the agent's
// file handling.
package elfutil

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
)

// ErrPatternNotFound is returned by FindCodePattern when the pattern does not
// occur in any executable segment.
var ErrPatternNotFound = errors.New("pattern not found in executable segments")

// FindCodePattern searches the executable PT_LOAD segments of an in-memory ELF
// image for pattern and returns the file offset and virtual address of the
// first match. Both are needed: the file offset is what a uprobe attaches to,
// and the virtual address is what a runtime memory scan would have found.
//
// The whole executable segment is read into memory before searching. Segments
// are bounded by the image size, and a caller that considers a binary hostile
// should check len(pattern) > 0; an empty pattern is rejected rather than
// matching at offset zero.
func FindCodePattern(image, pattern []byte) (offset, vaddr uint64, err error) {
	if len(image) == 0 {
		return 0, 0, errors.New("find code pattern: empty image")
	}
	if len(pattern) == 0 {
		return 0, 0, errors.New("find code pattern: empty pattern")
	}

	f, err := elf.NewFile(bytes.NewReader(image))
	if err != nil {
		return 0, 0, fmt.Errorf("find code pattern: parse ELF: %w", err)
	}
	defer f.Close()

	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == 0 {
			continue
		}
		if p.Filesz == 0 {
			continue
		}
		data := make([]byte, p.Filesz)
		if _, err := io.ReadFull(p.Open(), data); err != nil {
			// A truncated or unmapped segment is not fatal: keep looking.
			continue
		}
		idx := bytes.Index(data, pattern)
		if idx < 0 {
			continue
		}
		return p.Off + uint64(idx), p.Vaddr + uint64(idx), nil
	}
	return 0, 0, ErrPatternNotFound
}

// HexPattern decodes a hex string (optionally prefixed with 0x) into bytes.
// Odd-length strings are rejected because they cannot form whole bytes.
func HexPattern(s string) ([]byte, error) {
	s = trimHexPrefix(s)
	if s == "" {
		return nil, errors.New("hex pattern is empty")
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("hex pattern %q has an odd number of digits", s)
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, ok := hexNibble(s[2*i])
		if !ok {
			return nil, fmt.Errorf("hex pattern %q: invalid character %q", s, s[2*i])
		}
		lo, ok := hexNibble(s[2*i+1])
		if !ok {
			return nil, fmt.Errorf("hex pattern %q: invalid character %q", s, s[2*i+1])
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func trimHexPrefix(s string) string {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		return s[2:]
	}
	return s
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}
