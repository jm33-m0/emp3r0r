//go:build windows

package syscall

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Native PE Header definitions for 32-bit and 64-bit Windows
type IMAGE_DOS_HEADER struct {
	E_magic  uint16
	_        [58]byte
	E_lfanew int32
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_OPTIONAL_HEADER32 struct {
	Magic         uint16
	_             [94]byte
	DataDirectory [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_NT_HEADERS32 struct {
	Signature      uint32
	FileHeader     [20]byte
	OptionalHeader IMAGE_OPTIONAL_HEADER32
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic         uint16
	_             [110]byte
	DataDirectory [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     [20]byte
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

// IMAGE_SECTION_HEADER matches the native PE section table entry layout.
type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

// IMAGE_SCN_MEM_EXECUTE marks a section containing executable code.
const IMAGE_SCN_MEM_EXECUTE = 0x20000000

// executableRanges returns the [start, end) virtual address ranges of the
// executable sections in the PE image at base. The syscall gadget lives in
// the executable text section, so restricting scans to these ranges both
// speeds them up and avoids false positives from data sections.
func executableRanges(base uintptr) [][2]uintptr {
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(base))
	if dosHeader.E_magic != 0x5A4D { // "MZ"
		return nil
	}

	ntHeaderPtr := base + uintptr(dosHeader.E_lfanew)
	if *(*uint32)(unsafe.Pointer(ntHeaderPtr)) != 0x00004550 { // "PE\0\0"
		return nil
	}

	// IMAGE_FILE_HEADER layout: NumberOfSections at +2, SizeOfOptionalHeader at +16.
	numSections := int(*(*uint16)(unsafe.Pointer(ntHeaderPtr + 6)))
	sizeOfOptionalHeader := uintptr(*(*uint16)(unsafe.Pointer(ntHeaderPtr + 20)))
	sectionsPtr := ntHeaderPtr + 24 + sizeOfOptionalHeader

	var ranges [][2]uintptr
	for i := 0; i < numSections; i++ {
		sh := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(sectionsPtr + uintptr(i)*unsafe.Sizeof(IMAGE_SECTION_HEADER{})))
		if sh.Characteristics&IMAGE_SCN_MEM_EXECUTE == 0 {
			continue
		}

		size := uintptr(sh.VirtualSize)
		if uintptr(sh.SizeOfRawData) > size {
			size = uintptr(sh.SizeOfRawData)
		}
		if size == 0 {
			continue
		}

		start := base + uintptr(sh.VirtualAddress)
		ranges = append(ranges, [2]uintptr{start, start + size})
	}

	return ranges
}

// String converts a native UNICODE_STRING buffer into a standard Go string.
func (us *UNICODE_STRING) String() string {
	if us == nil || us.Buffer == nil || us.Length == 0 {
		return ""
	}
	// Length field represents byte count, so divide by 2 for UTF-16 character count
	charCount := us.Length / 2
	slice := unsafe.Slice(us.Buffer, charCount)
	return string(utf16.Decode(slice))
}

// Assembly function declared in peb_386.s / peb_amd64.s
func getPEBAddress() uintptr

// getExportDirectoryRVA returns the RVA of the Export Data Directory for PE32 or PE32+ module.
func getExportDirectoryRVA(base uintptr) (uint32, error) {
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(base))
	if dosHeader.E_magic != 0x5A4D { // "MZ"
		return 0, fmt.Errorf("invalid DOS header magic: 0x%x", dosHeader.E_magic)
	}

	ntHeaderPtr := base + uintptr(dosHeader.E_lfanew)
	signature := *(*uint32)(unsafe.Pointer(ntHeaderPtr))
	if signature != 0x00004550 { // "PE\0\0"
		return 0, fmt.Errorf("invalid NT header signature: 0x%x", signature)
	}

	magic := *(*uint16)(unsafe.Pointer(ntHeaderPtr + 24))
	switch magic {
	case 0x010B: // PE32
		nt32 := (*IMAGE_NT_HEADERS32)(unsafe.Pointer(ntHeaderPtr))
		return nt32.OptionalHeader.DataDirectory[0].VirtualAddress, nil
	case 0x020B: // PE32+
		nt64 := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(ntHeaderPtr))
		return nt64.OptionalHeader.DataDirectory[0].VirtualAddress, nil
	}

	return 0, fmt.Errorf("unsupported PE optional header magic: 0x%x", magic)
}

// ExtractSSN reads the System Service Number from an unhooked function address.
func ExtractSSN(funcVA uintptr) (uint32, error) {
	if funcVA == 0 {
		return 0, errors.New("invalid function address")
	}

	// Create a slice referencing the first 8 bytes of the function memory
	stubBytes := unsafe.Slice((*byte)(unsafe.Pointer(funcVA)), 8)

	// x64 preamble: 0x4C, 0x8B, 0xD1, 0xB8 -> mov r10, rcx; mov eax, <SSN>
	if stubBytes[0] == 0x4C && stubBytes[1] == 0x8B && stubBytes[2] == 0xD1 && stubBytes[3] == 0xB8 {
		ssn := binary.LittleEndian.Uint32(stubBytes[4:8])
		return ssn, nil
	}

	// x86 / standard preamble: 0xB8 -> mov eax, <SSN>
	if stubBytes[0] == 0xB8 {
		ssn := binary.LittleEndian.Uint32(stubBytes[1:5])
		return ssn, nil
	}

	return 0, errors.New("function stub signature check failed, function is likely hooked")
}

// GetModuleBaseAddress walks the PEB InMemoryOrderModuleList structure in memory
// and returns the base address of the requested DLL.
func GetModuleBaseAddress(moduleName string) uintptr {
	pebAddr := getPEBAddress()
	if pebAddr == 0 {
		return 0
	}

	ldrPtr := *(*uintptr)(unsafe.Pointer(pebAddr + pebLdrOffset))
	if ldrPtr == 0 {
		return 0
	}

	head := ldrPtr + ldrInMemoryOrderOffset
	curr := *(*uintptr)(unsafe.Pointer(head))

	targetLower := strings.ToLower(moduleName)

	// Iterate through the doubly-linked list until returning to the head
	for curr != head && curr != 0 {
		dllBase := *(*uintptr)(unsafe.Pointer(curr + ldrEntryDllBaseOffset))
		baseNameUnicode := (*UNICODE_STRING)(unsafe.Pointer(curr + ldrEntryBaseNameOffset))

		if dllBase != 0 && baseNameUnicode != nil {
			name := baseNameUnicode.String()
			if strings.ToLower(name) == targetLower {
				return dllBase
			}
		}

		// Advance to the Flink pointer of the next entry
		curr = *(*uintptr)(unsafe.Pointer(curr))
	}

	return 0
}

// GetCustomProcAddress parses the EAT of a DLL base address and resolves a function pointer.
func GetCustomProcAddress(dllBase uintptr, funcName string) uintptr {
	if dllBase == 0 {
		return 0
	}

	exportRVA, err := getExportDirectoryRVA(dllBase)
	if err != nil || exportRVA == 0 {
		return 0
	}

	exportDirVA := dllBase + uintptr(exportRVA)
	exportDir := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(exportDirVA))

	namesRVA := (*[1 << 24]uint32)(unsafe.Pointer(dllBase + uintptr(exportDir.AddressOfNames)))[:exportDir.NumberOfNames:exportDir.NumberOfNames]
	functionsRVA := (*[1 << 24]uint32)(unsafe.Pointer(dllBase + uintptr(exportDir.AddressOfFunctions)))[:exportDir.NumberOfFunctions:exportDir.NumberOfFunctions]
	ordinals := (*[1 << 24]uint16)(unsafe.Pointer(dllBase + uintptr(exportDir.AddressOfNameOrdinals)))[:exportDir.NumberOfNames:exportDir.NumberOfNames]

	for i := uint32(0); i < exportDir.NumberOfNames; i++ {
		currentNamePtr := (*byte)(unsafe.Pointer(dllBase + uintptr(namesRVA[i])))
		currentName := windows.BytePtrToString(currentNamePtr)

		if currentName == funcName {
			ordinal := ordinals[i]
			funcRVA := functionsRVA[ordinal]
			funcVA := dllBase + uintptr(funcRVA)

			// Handle Forwarded Exports (if address points within export directory)
			if funcVA >= exportDirVA && funcVA < (exportDirVA+0x10000) {
				forwarderStr := windows.BytePtrToString((*byte)(unsafe.Pointer(funcVA)))
				return resolveForwardedExport(forwarderStr)
			}

			return funcVA
		}
	}

	return 0
}

// resolveForwardedExport handles strings like "NTDLL.RtlAllocateHeap"
func resolveForwardedExport(forwarder string) uintptr {
	parts := strings.Split(forwarder, ".")
	if len(parts) != 2 {
		return 0
	}

	dllName := parts[0] + ".dll"
	functionName := parts[1]

	mod, err := windows.LoadLibrary(dllName)
	if err != nil {
		return 0
	}

	return GetCustomProcAddress(uintptr(mod), functionName)
}
