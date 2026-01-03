//go:build linux
// +build linux

package exeutil

import (
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// ELF constants
const (
	ELFCLASS32 = 1
	ELFCLASS64 = 2
)

var ELFMAGIC = []byte{0x7f, 'E', 'L', 'F'}

// ELFHeader represents the ELF header for both 32-bit and 64-bit binaries.
type ELFHeader struct {
	Ident          [16]byte
	Type           uint16
	Machine        uint16
	Version        uint32
	Entry          uint64
	Phoff          uint64
	Shoff          uint64
	Flags          uint32
	Ehsize         uint16
	Phentsize      uint16
	Phnum          uint16
	Shentsize      uint16
	Shnum          uint16
	Shstrndx       uint16
	ProgramHeaders []ProgramHeader
}

// Print prints the ELF header information.
func (h *ELFHeader) Print() {
	logging.Printf("ELF Header:")
	logging.Printf("  Entry Point:       0x%x", h.Entry)
	logging.Printf("  Program Header Off: %d", h.Phoff)
	logging.Printf("  Section Header Off: %d", h.Shoff)
	logging.Printf("  Number of PH:      %d", h.Phnum)
	logging.Printf("  Number of SH:      %d", h.Shnum)
	logging.Printf("  Size of PH Entry:  %d", h.Phentsize)
	for i, ph := range h.ProgramHeaders {
		ph.Print(i)
	}
}

// ProgHeader64 represents a 64-bit ELF program header.
type ProgHeader64 struct {
	Type   uint32
	Flags  uint32
	Off    uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64
}

// ProgHeader32 represents a 32-bit ELF program header.
type ProgHeader32 struct {
	Type   uint32
	Off    uint32
	Vaddr  uint32
	Paddr  uint32
	Filesz uint32
	Memsz  uint32
	Flags  uint32
	Align  uint32
}

// ProgramHeader represents a generic ELF program header.
type ProgramHeader struct {
	Type   uint32
	Flags  uint32
	Off    uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64
}

// Print prints the program header information.
func (ph *ProgramHeader) Print(index int) {
	logging.Printf("  [%d] Type: 0x%x, Offset: 0x%x, VAddr: 0x%x, PAddr: 0x%x", index, ph.Type, ph.Off, ph.Vaddr, ph.Paddr)
	logging.Printf("      File Size: %d, Mem Size: %d, Flags: 0x%x, Align: %d", ph.Filesz, ph.Memsz, ph.Flags, ph.Align)
}

// SectionHeader32 represents a 32-bit ELF section header.
type SectionHeader32 struct {
	Name      uint32
	Type      uint32
	Flags     uint32
	Addr      uint32
	Offset    uint32
	Size      uint32
	Link      uint32
	Info      uint32
	Addralign uint32
	Entsize   uint32
}

// Dynamic32 represents a 32-bit ELF dynamic entry.
type Dynamic32 struct {
	Tag int32
	Val uint32
}

// SectionHeader represents an ELF section header.
type SectionHeader struct {
	Name      uint32
	Type      uint32
	Flags     uint64
	Addr      uint64
	Offset    uint64
	Size      uint64
	Link      uint32
	Info      uint32
	Addralign uint64
	Entsize   uint64
}

// Dynamic represents an ELF dynamic entry.
type Dynamic struct {
	Tag int64
	Val uint64
}

// ELF section types
const (
	SHT_DYNAMIC = 6
	SHT_STRTAB  = 3
)

// ELF section flags
const (
	SHF_ALLOC = 0x2
)

// ELF dynamic tags
const (
	DT_NULL   = 0
	DT_NEEDED = 1
)

// GetSymFromLibc gets the pointer to a libc function that is currently loaded in the target process, ASLR-proof.
// Parameters:
// - pid: Process ID of the target process.
// - sym: Name of the symbol to find.
func GetSymFromLibc(pid int, sym string) (addr int64, err error) {
	libc_path, base, offset, err := GetLibc(pid)
	if base == 0 || err != nil {
		err = fmt.Errorf("libc not found: %v", err)
		return
	}
	elf_file, err := elf.Open(libc_path)
	if err != nil {
		err = fmt.Errorf("ELF open: %v", err)
		return
	}
	defer elf_file.Close()
	syms, err := elf_file.DynamicSymbols()
	if err != nil {
		err = fmt.Errorf("ELF symbols: %v", err)
		return
	}
	for _, s := range syms {
		if strings.Contains(s.Name, sym) {
			addr = base + int64(s.Value) - offset
			break
		}
	}
	if addr == 0 {
		err = fmt.Errorf("scanned %d symbols, symbol (addr 0x%x) %s not found", len(syms), addr, sym)
		return
	}
	logging.Printf("Address of %s is 0x%x", sym, addr)

	return
}

// GetLibc gets the base address, ASLR offset value, and path of libc by parsing /proc/pid/maps.
// Parameters:
// - pid: Process ID of the target process.
func GetLibc(pid int) (path string, addr, offset int64, err error) {
	map_path := fmt.Sprintf("/proc/%d/maps", pid)

	f, err := os.Open(map_path)
	if err != nil {
		err = fmt.Errorf("open %s: %v", map_path, err)
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		isLibc := strings.Contains(line, "libc.so") && strings.Contains(line, " r-xp ")
		if !isLibc {
			continue
		}
		fields := strings.Fields(line)
		addr, _ = strconv.ParseInt(strings.Split(line, "-")[0], 16, 64)
		offset, _ = strconv.ParseInt(fields[2], 16, 64)

		path = fields[len(fields)-1]
		logging.Printf("libc base addr is 0x%x, offset is 0x%x, path is %s",
			addr, offset, path)
		break
	}

	// check if we got the right libc
	if path == "" {
		err = fmt.Errorf("scanned map file, libc not found")
	}

	return
}

// IsELF checks if a file is an ELF file.
// Parameters:
// - file: Path to the file to check.
func IsELF(file string) bool {
	f, err := os.Open(file)
	if err != nil {
		return false
	}
	defer f.Close()
	_, err = elf.NewFile(f)
	return err == nil
}

// IsStaticELF checks if the given ELF file is statically linked.
// Parameters:
// - file_path: Path to the ELF file to check.
func IsStaticELF(file_path string) bool {
	f, err := elf.Open(file_path)
	if err != nil {
		logging.Printf("Error opening ELF file: %v", err)
		return false
	}
	defer f.Close()

	// Check if the ELF file is statically linked
	isStaticallyLinked := true
	for _, phdr := range f.Progs {
		if phdr.Type == elf.PT_DYNAMIC {
			isStaticallyLinked = false
			break
		}
	}
	return isStaticallyLinked
}

// ParseELFHeaders parses ELF headers from the given byte slice.
// Parameters:
// - data: Byte slice containing the ELF file data.
func ParseELFHeaders(data []byte) (*ELFHeader, error) {
	reader := bytes.NewReader(data)

	// Verify ELF magic number
	var ident [16]byte
	if _, err := reader.Read(ident[:]); err != nil {
		return nil, err
	}
	if !bytes.Equal(ident[:4], ELFMAGIC) {
		return nil, fmt.Errorf("invalid ELF magic number")
	}

	// Determine ELF class (32-bit or 64-bit)
	class := ident[4]
	switch class {
	case ELFCLASS64:
		return ParseELF64(reader, ident)
	case ELFCLASS32:
		return ParseELF32(reader, ident)
	}
	return nil, fmt.Errorf("unsupported ELF class: %v", class)
}

// ParseELF64 parses the ELF header for 64-bit binaries.
// Parameters:
// - reader: Reader for the ELF file data.
// - ident: ELF identification bytes.
func ParseELF64(reader *bytes.Reader, ident [16]byte) (*ELFHeader, error) {
	var header ELFHeader
	header.Ident = ident
	if err := binary.Read(reader, binary.LittleEndian, &header.Type); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Machine); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Version); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Entry); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Phoff); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Shoff); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Flags); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Ehsize); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Phentsize); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Phnum); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Shentsize); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Shnum); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Shstrndx); err != nil {
		return nil, err
	}

	// Read program headers
	headers, err := parseProgramHeaders(reader, int64(header.Phoff), int(header.Phnum), ELFCLASS64)
	if err != nil {
		return nil, err
	}
	header.ProgramHeaders = headers

	return &header, nil
}

// ParseELF32 parses the ELF header for 32-bit binaries.
// Parameters:
// - reader: Reader for the ELF file data.
// - ident: ELF identification bytes.
func ParseELF32(reader *bytes.Reader, ident [16]byte) (*ELFHeader, error) {
	var header ELFHeader
	header.Ident = ident
	if err := binary.Read(reader, binary.LittleEndian, &header.Type); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Machine); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Version); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Entry); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Phoff); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Shoff); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Flags); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Ehsize); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Phentsize); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Phnum); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Shentsize); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Shnum); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.Shstrndx); err != nil {
		return nil, err
	}

	// Read program headers
	headers, err := parseProgramHeaders(reader, int64(header.Phoff), int(header.Phnum), ELFCLASS32)
	if err != nil {
		return nil, err
	}
	header.ProgramHeaders = headers

	return &header, nil
}

// parseProgramHeaders parses the program headers from the given reader.
// Parameters:
// - reader: Reader for the ELF file data.
// - phOff: Offset to the program headers.
// - phNum: Number of program headers.
// - elfClass: ELF class (32-bit or 64-bit).
func parseProgramHeaders(reader *bytes.Reader, phOff int64, phNum int, elfClass byte) ([]ProgramHeader, error) {
	if _, err := reader.Seek(phOff, 0); err != nil {
		return nil, err
	}

	var headers []ProgramHeader
	for i := 0; i < phNum; i++ {
		var ph ProgramHeader
		if elfClass == ELFCLASS64 {
			var ph64 ProgHeader64
			if err := binary.Read(reader, binary.LittleEndian, &ph64); err != nil {
				return nil, err
			}
			ph = ProgramHeader(ph64)
		} else {
			var ph32 ProgHeader32
			if err := binary.Read(reader, binary.LittleEndian, &ph32); err != nil {
				return nil, err
			}
			ph = ProgramHeader{
				Type:   ph32.Type,
				Flags:  ph32.Flags,
				Off:    uint64(ph32.Off),
				Vaddr:  uint64(ph32.Vaddr),
				Paddr:  uint64(ph32.Paddr),
				Filesz: uint64(ph32.Filesz),
				Memsz:  uint64(ph32.Memsz),
				Align:  uint64(ph32.Align),
			}
		}
		headers = append(headers, ph)
	}
	return headers, nil
}

// AddDTNeeded adds a specified library to the DT_NEEDED entries of an ELF file.
// Parameters:
// - filePath: Path to the ELF file to modify.
// - libName: Name of the library to add.
func AddDTNeeded(filePath, libName string) error {
	f, err := os.OpenFile(filePath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("error opening ELF file: %v", err)
	}
	defer f.Close()

	// Read the ELF file header
	var ident [16]byte
	if _, err := f.Read(ident[:]); err != nil {
		return fmt.Errorf("error reading ELF identification: %v", err)
	}
	if !bytes.Equal(ident[:4], ELFMAGIC) {
		return fmt.Errorf("invalid ELF magic number")
	}

	// Determine ELF class (32-bit or 64-bit)
	class := ident[4]
	var header *ELFHeader
	elf_bytes, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("error reading ELF file: %v", err)
	}
	header, err = ParseELFHeaders(elf_bytes)
	if err != nil {
		return fmt.Errorf("error parsing ELF header: %v", err)
	}

	// Read the section headers
	sectionHeaders, err := parseSectionHeaders(f, header.Shoff, int(header.Shnum), class)
	if err != nil {
		return fmt.Errorf("error parsing section headers: %v", err)
	}

	// Find the dynamic section and string table
	var dynSection, strTabSection *SectionHeader
	for i := range sectionHeaders {
		if sectionHeaders[i].Type == SHT_DYNAMIC {
			dynSection = &sectionHeaders[i]
		}
		if sectionHeaders[i].Type == SHT_STRTAB && sectionHeaders[i].Flags&SHF_ALLOC != 0 {
			strTabSection = &sectionHeaders[i]
		}
	}
	if dynSection == nil {
		return fmt.Errorf("dynamic section not found")
	}
	if strTabSection == nil {
		return fmt.Errorf("string table not found")
	}

	// Read the dynamic entries
	dynEntries, err := parseDynamicEntries(f, dynSection.Offset, dynSection.Size, class)
	if err != nil {
		return fmt.Errorf("error parsing dynamic entries: %v", err)
	}

	// Read the string table
	strTabData, err := readSectionData(f, strTabSection.Offset, strTabSection.Size)
	if err != nil {
		return fmt.Errorf("error reading string table: %v", err)
	}

	// Add the new library to the string table
	newStrTabData := append(strTabData, []byte(libName)...)
	newStrTabData = append(newStrTabData, 0) // Null-terminate the string

	// Update the dynamic entries
	for i := range dynEntries {
		if dynEntries[i].Tag == DT_NULL {
			dynEntries[i].Tag = DT_NEEDED
			dynEntries[i].Val = uint64(len(strTabData))
			break
		}
	}

	// Write the updated string table back to the file
	if err := writeSectionData(f, strTabSection.Offset, newStrTabData); err != nil {
		return fmt.Errorf("error writing string table: %v", err)
	}

	// Write the updated dynamic entries back to the file
	if err := writeDynamicEntries(f, dynSection.Offset, dynEntries, class); err != nil {
		return fmt.Errorf("error writing dynamic entries: %v", err)
	}

	return nil
}

// parseSectionHeaders parses the section headers from the given file.
// Parameters:
// - f: File containing the ELF data.
// - shOff: Offset to the section headers.
// - shNum: Number of section headers.
// - elfClass: ELF class (32-bit or 64-bit).
func parseSectionHeaders(f *os.File, shOff uint64, shNum int, elfClass byte) ([]SectionHeader, error) {
	if _, err := f.Seek(int64(shOff), 0); err != nil {
		return nil, err
	}

	var headers []SectionHeader
	for i := 0; i < shNum; i++ {
		var sh SectionHeader
		if elfClass == ELFCLASS64 {
			if err := binary.Read(f, binary.LittleEndian, &sh); err != nil {
				return nil, err
			}
		} else {
			var sh32 SectionHeader32
			if err := binary.Read(f, binary.LittleEndian, &sh32); err != nil {
				return nil, err
			}
			sh = SectionHeader{
				Name:      sh32.Name,
				Type:      sh32.Type,
				Flags:     uint64(sh32.Flags),
				Addr:      uint64(sh32.Addr),
				Offset:    uint64(sh32.Offset),
				Size:      uint64(sh32.Size),
				Link:      sh32.Link,
				Info:      sh32.Info,
				Addralign: uint64(sh32.Addralign),
				Entsize:   uint64(sh32.Entsize),
			}
		}
		headers = append(headers, sh)
	}
	return headers, nil
}

// parseDynamicEntries parses the dynamic entries from the given file.
// Parameters:
// - f: File containing the ELF data.
// - dynOff: Offset to the dynamic entries.
// - dynSize: Size of the dynamic entries.
// - elfClass: ELF class (32-bit or 64-bit).
func parseDynamicEntries(f *os.File, dynOff uint64, dynSize uint64, elfClass byte) ([]Dynamic, error) {
	if _, err := f.Seek(int64(dynOff), 0); err != nil {
		return nil, err
	}

	var entries []Dynamic
	for i := uint64(0); i < dynSize/uint64(binary.Size(Dynamic{})); i++ {
		var dyn Dynamic
		if elfClass == ELFCLASS64 {
			if err := binary.Read(f, binary.LittleEndian, &dyn); err != nil {
				return nil, err
			}
		} else {
			var dyn32 Dynamic32
			if err := binary.Read(f, binary.LittleEndian, &dyn32); err != nil {
				return nil, err
			}
			dyn = Dynamic{
				Tag: int64(dyn32.Tag),
				Val: uint64(dyn32.Val),
			}
		}
		entries = append(entries, dyn)
	}
	return entries, nil
}

// readSectionData reads the data of a section from the given file.
// Parameters:
// - f: File containing the ELF data.
// - offset: Offset to the section data.
// - size: Size of the section data.
func readSectionData(f *os.File, offset uint64, size uint64) ([]byte, error) {
	if _, err := f.Seek(int64(offset), 0); err != nil {
		return nil, err
	}
	data := make([]byte, size)
	if _, err := f.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}

// writeSectionData writes the data to a section in the given file.
// Parameters:
// - f: File containing the ELF data.
// - offset: Offset to the section data.
// - data: Data to write to the section.
func writeSectionData(f *os.File, offset uint64, data []byte) error {
	if _, err := f.Seek(int64(offset), 0); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	return nil
}

// writeDynamicEntries writes the dynamic entries to the given file.
// Parameters:
// - f: File containing the ELF data.
// - offset: Offset to the dynamic entries.
// - entries: Dynamic entries to write.
// - elfClass: ELF class (32-bit or 64-bit).
func writeDynamicEntries(f *os.File, offset uint64, entries []Dynamic, elfClass byte) error {
	if _, err := f.Seek(int64(offset), 0); err != nil {
		return err
	}
	for _, entry := range entries {
		if elfClass == ELFCLASS64 {
			if err := binary.Write(f, binary.LittleEndian, entry); err != nil {
				return err
			}
		} else {
			entry32 := Dynamic32{
				Tag: int32(entry.Tag),
				Val: uint32(entry.Val),
			}
			if err := binary.Write(f, binary.LittleEndian, entry32); err != nil {
				return err
			}
		}
	}
	return nil
}

// FixELF replaces ld and adds rpath to use musl libc.
// Parameters:
// - elf_path: Path to the ELF file to fix.
func FixELF(elf_path, rpath, ld_path string) (err error) {
	// see module vaccine's directory structure
	utils_path := filepath.Dir(filepath.Dir(rpath))
	pwd, _ := os.Getwd()
	err = os.Chdir(utils_path)
	if err != nil {
		return
	}
	defer os.Chdir(pwd)

	// paths
	patchelf := fmt.Sprintf("%s/patchelf", utils_path)
	logging.Printf("rpath: %s, patchelf: %s, ld_path: %s", rpath, patchelf, ld_path)

	// remove rpath
	cmd := fmt.Sprintf("%s --remove-rpath", patchelf)
	out, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("patchelf remove rpath: %v, %s", err, out)
	}

	// patchelf cmd
	cmd = fmt.Sprintf("%s --set-interpreter %s --set-rpath %s %s",
		patchelf, ld_path, rpath, elf_path)

	out, err = exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("patchelf: %v, %s", err, out)
	}
	return
}
