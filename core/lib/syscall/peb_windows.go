//go:build windows

package syscall

import (
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Native PE Header definitions for 64-bit Windows
type IMAGE_DOS_HEADER struct {
	E_magic  uint16
	_        [58]byte
	E_lfanew int32
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
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

// UNICODE_STRING matches the native NT structure layout on 64-bit Windows.
type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	_             uint32 // Padding for 8-byte alignment on x64
	Buffer        *uint16
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

// Assembly function declared in peb_amd64.s
func getPEBAddress() uintptr

// ExtractSSN reads the System Service Number from an unhooked function address.
func ExtractSSN(funcVA uintptr) (uint32, error) {
	if funcVA == 0 {
		return 0, errors.New("invalid function address")
	}

	// Create a slice referencing the first 8 bytes of the function memory
	stubBytes := unsafe.Slice((*byte)(unsafe.Pointer(funcVA)), 8)

	// Verify standard unhooked x64 syscall preamble:
	// 0x4C, 0x8B, 0xD1 -> mov r10, rcx
	// 0xB8             -> mov eax, <SSN>
	isUnhooked := stubBytes[0] == 0x4C &&
		stubBytes[1] == 0x8B &&
		stubBytes[2] == 0xD1 &&
		stubBytes[3] == 0xB8

	if !isUnhooked {
		return 0, errors.New("function stub signature check failed, function is likely hooked")
	}

	// Extract the 32-bit SSN starting from offset 4
	ssn := binary.LittleEndian.Uint32(stubBytes[4:8])
	return ssn, nil
}

// GetModuleBaseAddress walks the PEB InMemoryOrderModuleList structure in memory
// and returns the base address of the requested DLL.
func GetModuleBaseAddress(moduleName string) uintptr {
	pebAddr := getPEBAddress()
	if pebAddr == 0 {
		return 0
	}

	// PEB -> Ldr pointer is located at offset 0x18 on 64-bit Windows
	ldrPtr := *(*uintptr)(unsafe.Pointer(pebAddr + 0x18))
	if ldrPtr == 0 {
		return 0
	}

	// PEB_LDR_DATA -> InMemoryOrderModuleList LIST_ENTRY is at offset 0x20
	head := ldrPtr + 0x20
	curr := *(*uintptr)(unsafe.Pointer(head))

	targetLower := strings.ToLower(moduleName)

	// Iterate through the doubly-linked list until returning to the head
	for curr != head && curr != 0 {
		// Memory Offsets relative to InMemoryOrderLinks (offset 0x10 in LDR_DATA_TABLE_ENTRY):
		// DllBase is at struct offset 0x30, which equals curr + 0x20
		// BaseDllName is at struct offset 0x58, which equals curr + 0x48
		dllBase := *(*uintptr)(unsafe.Pointer(curr + 0x20))
		baseNameUnicode := (*UNICODE_STRING)(unsafe.Pointer(curr + 0x48))

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

	// 1. Verify DOS Header
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(dllBase))
	if dosHeader.E_magic != 0x5A4D { // "MZ"
		return 0
	}

	// 2. Verify NT Headers
	ntHeaders := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(dllBase + uintptr(dosHeader.E_lfanew)))
	if ntHeaders.Signature != 0x00004550 { // "PE\0\0"
		return 0
	}

	// 3. Locate Export Directory
	exportDirData := ntHeaders.OptionalHeader.DataDirectory[0] // IMAGE_DIRECTORY_ENTRY_EXPORT
	if exportDirData.VirtualAddress == 0 {
		return 0
	}

	exportDirVA := dllBase + uintptr(exportDirData.VirtualAddress)
	exportDirSize := uintptr(exportDirData.Size)
	exportDir := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(exportDirVA))

	// 4. Map PE Parallel Arrays
	namesRVA := (*[1 << 24]uint32)(unsafe.Pointer(dllBase + uintptr(exportDir.AddressOfNames)))[:exportDir.NumberOfNames:exportDir.NumberOfNames]
	functionsRVA := (*[1 << 24]uint32)(unsafe.Pointer(dllBase + uintptr(exportDir.AddressOfFunctions)))[:exportDir.NumberOfFunctions:exportDir.NumberOfFunctions]
	ordinals := (*[1 << 24]uint16)(unsafe.Pointer(dllBase + uintptr(exportDir.AddressOfNameOrdinals)))[:exportDir.NumberOfNames:exportDir.NumberOfNames]

	// 5. Search for export name
	for i := uint32(0); i < exportDir.NumberOfNames; i++ {
		currentNamePtr := (*byte)(unsafe.Pointer(dllBase + uintptr(namesRVA[i])))
		currentName := windows.BytePtrToString(currentNamePtr)

		if currentName == funcName {
			ordinal := ordinals[i]
			funcRVA := functionsRVA[ordinal]
			funcVA := dllBase + uintptr(funcRVA)

			// 6. Handle Forwarded Exports
			if funcVA >= exportDirVA && funcVA < (exportDirVA+exportDirSize) {
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

	// Get base address of target DLL (e.g., via PEB walk)
	mod, err := windows.LoadLibrary(dllName)
	if err != nil {
		return 0
	}

	return GetCustomProcAddress(uintptr(mod), functionName)
}
