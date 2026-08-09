//go:build windows

package syscall

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type exportEntry struct {
	Name    string
	Address uintptr
}

// Standard NTSTATUS return codes
const (
	STATUS_SUCCESS uint32 = 0x00000000
)

// CLIENT_ID identifies a target process and thread
type CLIENT_ID struct {
	UniqueProcess windows.Handle
	UniqueThread  windows.Handle
}

// OBJECT_ATTRIBUTES specifies attributes applied to objects
type OBJECT_ATTRIBUTES struct {
	Length                   uint32
	RootDirectory            windows.Handle
	ObjectName               uintptr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

// SyscallInfo holds the execution parameters for an indirect system call
type SyscallInfo struct {
	SSN        uint32
	GadgetAddr uintptr
}

// SyscallTable manages the resolved system calls in memory
type SyscallTable struct {
	mu         sync.RWMutex
	ntdllBase  uintptr
	gadgetAddr uintptr
	syscalls   map[string]SyscallInfo
}

// Caches SyscallTable for later use
var RuntimeSyscallTable *SyscallTable

// Assembly primitive declaration accepting variadic slice
func executeSyscall(ssn uint32, gadget uintptr, args []uintptr) uint32

// InvokeSyscall executes any NT system call via indirect syscall using variadic arguments
func (table *SyscallTable) InvokeSyscall(name string, args ...uintptr) (uint32, error) {
	info, found := table.GetSyscall(name)
	if !found {
		return 0, fmt.Errorf("system call %s not found in table", name)
	}

	status := executeSyscall(info.SSN, info.GadgetAddr, args)
	return status, nil
}

// Scan ntdll memory for a 'syscall; ret' gadget (0x0F 0x05 0xC3)
func findSyscallGadget(ntdllBase uintptr) uintptr {
	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(ntdllBase))
	ntHeaders := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(ntdllBase + uintptr(dosHeader.E_lfanew)))

	// Search within .text section or first 0x100000 bytes of ntdll
	searchSize := uintptr(ntHeaders.OptionalHeader.DataDirectory[0].VirtualAddress)
	if searchSize == 0 {
		searchSize = 0x100000
	}

	buffer := unsafe.Slice((*byte)(unsafe.Pointer(ntdllBase)), searchSize)
	gadgetPattern := []byte{0x0F, 0x05, 0xC3}

	index := bytes.Index(buffer, gadgetPattern)
	if index != -1 {
		return ntdllBase + uintptr(index)
	}

	return 0
}

// InitializeSyscallTable builds the complete map of SSNs and gadget locations
func InitializeSyscallTable() (*SyscallTable, error) {
	ntdllBase := GetModuleBaseAddress("ntdll.dll")
	if ntdllBase == 0 {
		return nil, fmt.Errorf("failed to locate ntdll.dll in PEB")
	}

	gadgetAddr := findSyscallGadget(ntdllBase)
	if gadgetAddr == 0 {
		return nil, fmt.Errorf("failed to locate syscall gadget in ntdll.dll")
	}

	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(ntdllBase))
	ntHeaders := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(ntdllBase + uintptr(dosHeader.E_lfanew)))
	exportDirVA := ntdllBase + uintptr(ntHeaders.OptionalHeader.DataDirectory[0].VirtualAddress)
	exportDir := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(exportDirVA))

	namesRVA := (*[1 << 24]uint32)(unsafe.Pointer(ntdllBase + uintptr(exportDir.AddressOfNames)))[:exportDir.NumberOfNames:exportDir.NumberOfNames]
	functionsRVA := (*[1 << 24]uint32)(unsafe.Pointer(ntdllBase + uintptr(exportDir.AddressOfFunctions)))[:exportDir.NumberOfFunctions:exportDir.NumberOfFunctions]
	ordinals := (*[1 << 24]uint16)(unsafe.Pointer(ntdllBase + uintptr(exportDir.AddressOfNameOrdinals)))[:exportDir.NumberOfNames:exportDir.NumberOfNames]

	var entries []exportEntry

	// Step 3: Collect all Zw exports to avoid duplicate Nt aliases
	for i := uint32(0); i < exportDir.NumberOfNames; i++ {
		currentNamePtr := (*byte)(unsafe.Pointer(ntdllBase + uintptr(namesRVA[i])))
		name := bytePtrToString(currentNamePtr)

		if strings.HasPrefix(name, "Zw") {
			ordinal := ordinals[i]
			funcVA := ntdllBase + uintptr(functionsRVA[ordinal])

			entries = append(entries, exportEntry{
				Name:    "Nt" + name[2:],
				Address: funcVA,
			})
		}
	}

	// Sort functions by virtual address to calculate SSNs
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Address < entries[j].Address
	})

	// Step 4: Populate the consolidated lookup map
	table := &SyscallTable{
		ntdllBase:  ntdllBase,
		gadgetAddr: gadgetAddr,
		syscalls:   make(map[string]SyscallInfo),
	}

	for ssn, entry := range entries {
		table.syscalls[entry.Name] = SyscallInfo{
			SSN:        uint32(ssn),
			GadgetAddr: gadgetAddr,
		}
	}

	return table, nil
}

// GetSyscall retrieves the SSN and gadget address for a target system call
func (t *SyscallTable) GetSyscall(name string) (SyscallInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	info, exists := t.syscalls[name]
	return info, exists
}

func bytePtrToString(ptr *byte) string {
	if ptr == nil {
		return ""
	}
	var length int
	for *(*byte)(unsafe.Add(unsafe.Pointer(ptr), length)) != 0 {
		length++
	}
	slice := unsafe.Slice(ptr, length)
	return string(slice)
}
