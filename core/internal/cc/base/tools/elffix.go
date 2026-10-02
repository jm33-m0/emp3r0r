package tools

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
)

// materializeInitArray copies R_*_RELATIVE addends into the ELF
// .preinit_array/.init_array slots that are zero in the file image.
//
// lld (zig's linker) stores the R_X86_64_RELATIVE/R_AARCH64_RELATIVE addend only
// in the RELA entry and leaves the referenced slot zero, while GNU ld also
// writes the addend into the slot itself. malasada reads the arrays statically
// to call the Go runtime constructors, so a zig-linked agent .so would
// otherwise start with an empty init array and never initialize its runtime.
// Non-RELATIVE and already-materialized entries are left untouched, so this is
// a no-op for gcc-linked objects.
func materializeInitArray(so []byte) ([]byte, error) {
	f, err := elf.NewFile(bytes.NewReader(so))
	if err != nil {
		return nil, fmt.Errorf("parse ELF: %w", err)
	}
	defer func() { _ = f.Close() }()

	relaSec := f.Section(".rela.dyn")
	if relaSec == nil {
		return so, nil
	}
	rela, err := relaSec.Data()
	if err != nil {
		return nil, fmt.Errorf("read .rela.dyn: %w", err)
	}

	const relaEntSize = 24
	addends := make(map[uint64]uint64)
	for off := 0; off+relaEntSize <= len(rela); off += relaEntSize {
		entry := rela[off : off+relaEntSize]
		rOffset := binary.LittleEndian.Uint64(entry[0:8])
		rInfo := binary.LittleEndian.Uint64(entry[8:16])
		if !isRelativeReloc(f.Machine, rInfo) {
			continue
		}
		addends[rOffset] = binary.LittleEndian.Uint64(entry[16:24])
	}
	if len(addends) == 0 {
		return so, nil
	}

	out := bytes.Clone(so)
	for _, name := range []string{".preinit_array", ".init_array"} {
		sec := f.Section(name)
		if sec == nil {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		for i := 0; i+8 <= len(data); i += 8 {
			if binary.LittleEndian.Uint64(data[i:i+8]) != 0 {
				continue
			}
			addend, ok := addends[sec.Addr+uint64(i)]
			if !ok {
				continue
			}
			slot := sec.Offset + uint64(i)
			if slot+8 > uint64(len(out)) {
				return nil, fmt.Errorf("%s slot outside file", name)
			}
			binary.LittleEndian.PutUint64(out[slot:slot+8], addend)
		}
	}
	return out, nil
}

// isRelativeReloc reports whether rInfo encodes a base-relative relocation for
// the given ELF machine. rInfo's low 32 bits are the relocation type.
func isRelativeReloc(machine elf.Machine, rInfo uint64) bool {
	rType := uint32(rInfo)
	switch machine {
	case elf.EM_X86_64:
		return elf.R_X86_64(rType) == elf.R_X86_64_RELATIVE
	case elf.EM_AARCH64:
		return elf.R_AARCH64(rType) == elf.R_AARCH64_RELATIVE
	case elf.EM_386:
		return elf.R_386(rType) == elf.R_386_RELATIVE
	case elf.EM_ARM:
		return elf.R_ARM(rType) == elf.R_ARM_RELATIVE
	default:
		return false
	}
}
