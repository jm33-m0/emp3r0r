//go:build windows
// +build windows

package util

import (
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/sys/windows"
)

func IsRunningInDLL() bool {
	modHandle, _, _ := procGetModuleHandle.Call(0)
	return modHandle != 0
}

func ReadDLL(moduleInfo *windows.ModuleInfo, fileName string) (dll_data []byte, err error) {
	// Allocate a buffer to hold the DLL content
	dllContent := make([]byte, moduleInfo.SizeOfImage)

	// Read the content of the DLL from memory
	var bytes_read uintptr
	err = windows.ReadProcessMemory(windows.CurrentProcess(), moduleInfo.BaseOfDll, &dllContent[0],
		uintptr(moduleInfo.SizeOfImage), &bytes_read)
	if err != nil {
		err = fmt.Errorf("failed to get module info of %s: %v", fileName, err)
		return
	}
	dll_data = dllContent
	return
}

// Enum all DLLs and get their handles
func GetAllDLLs() (modules map[string]*windows.ModuleInfo, err error) {
	modules = make(map[string]*windows.ModuleInfo, 0)

	// Open a handle to the current process
	processHandle := windows.CurrentProcess()

	// Enumerate the modules (DLLs) loaded in the current process
	var moduleHandles = make([]windows.Handle, 1024)
	var neededBytes uint32
	err = windows.EnumProcessModules(processHandle, &moduleHandles[0], 1024, &neededBytes)
	if err != nil {
		err = fmt.Errorf("enum modules: %v", err)
		return
	}

	// Calculate the number of modules
	numModules := int(neededBytes / uint32(unsafe.Sizeof(moduleHandles[0])))

	// Print the file names of the loaded DLLs
	for i := 0; i < numModules; i++ {
		// Get the file name of the DLL
		var fname16 = make([]uint16, windows.MAX_PATH)
		_, err = windows.GetModuleFileName(moduleHandles[i], &fname16[0], windows.MAX_PATH)
		if err != nil {
			log.Printf("get module file name: %v", err)
			continue
		}
		// Convert the UTF-16 encoded file name to a Go string
		fileName := windows.UTF16ToString(fname16)

		// get module info
		modinfo := new(windows.ModuleInfo)
		cb := uint32(unsafe.Sizeof(*modinfo))
		err = windows.GetModuleInformation(processHandle, moduleHandles[i], modinfo, cb)
		if err != nil {
			log.Printf("get modinfo of %s: %v", fileName, err)
			continue
		}
		modules[fileName] = modinfo
	}

	return
}
