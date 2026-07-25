//go:build windows

package script

import (
	"fmt"
	"sync"
	"unsafe"

	"go.starlark.net/starlark"
	"golang.org/x/sys/windows"
)

var (
	dllCacheMu sync.RWMutex
	dllCache   = make(map[string]*windows.LazyDLL)

	kernel32Mod                        = windows.NewLazySystemDLL("kernel32.dll")
	procAddVectoredExceptionHandler    = kernel32Mod.NewProc("AddVectoredExceptionHandler")
	procRemoveVectoredExceptionHandler = kernel32Mod.NewProc("RemoveVectoredExceptionHandler")

	scriptVEHOnce          sync.Once
	scriptVEHHandle        uintptr
	scriptRecoveryCallback uintptr
	scriptInWinCall        bool
	scriptExceptionCode    uint32
	scriptExceptionAddr    uintptr
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

func initScriptVEH() {
	scriptVEHOnce.Do(func() {
		scriptRecoveryCallback = windows.NewCallback(scriptRecoveryStub)
		cb := windows.NewCallback(scriptVEHHandler)
		ret, _, _ := procAddVectoredExceptionHandler.Call(1, cb)
		scriptVEHHandle = ret
	})
}

func scriptRecoveryStub() uintptr {
	panic(fmt.Sprintf("native Win32 exception 0x%X at address 0x%X", scriptExceptionCode, scriptExceptionAddr))
}

func scriptVEHHandler(exceptionPointers uintptr) uintptr {
	if exceptionPointers == 0 || !scriptInWinCall {
		return 0 // EXCEPTION_CONTINUE_SEARCH
	}

	ep := (*exceptionPointersStruct)(unsafe.Pointer(exceptionPointers))
	if ep == nil || ep.ExceptionRecord == nil || ep.ContextRecord == 0 {
		return 0
	}

	code := ep.ExceptionRecord.ExceptionCode
	if code >= 0x80000000 {
		scriptExceptionCode = code
		scriptExceptionAddr = ep.ExceptionRecord.ExceptionAddress
		scriptInWinCall = false

		if unsafe.Sizeof(uintptr(0)) == 8 {
			// 64-bit AMD64: RIP offset is 0xF8 (248) inside CONTEXT
			*(*uintptr)(unsafe.Pointer(ep.ContextRecord + 0xF8)) = scriptRecoveryCallback
		} else {
			// 32-bit x86: EIP offset is 0xB4 (180) inside CONTEXT
			*(*uintptr)(unsafe.Pointer(ep.ContextRecord + 0xB4)) = scriptRecoveryCallback
		}

		return ^uintptr(0) // EXCEPTION_CONTINUE_EXECUTION (-1)
	}

	return 0
}

// getLazyProc retrieves a cached reference to a system module or initialises a new handle dynamically
func getLazyProc(dllName, procName string) *windows.LazyProc {
	dllCacheMu.Lock()
	defer dllCacheMu.Unlock()

	dll, exists := dllCache[dllName]
	if !exists {
		dll = windows.NewLazySystemDLL(dllName)
		dllCache[dllName] = dll
	}
	return dll.NewProc(procName)
}

// starlarkWinCall provides an interface to execute any function within a specified DLL dynamically
func starlarkWinCall(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (retVal starlark.Value, retErr error) {
	if len(args) < 2 {
		return starlark.None, fmt.Errorf("win_call requires at least a DLL name and a procedure name")
	}

	dllName, ok := starlark.AsString(args[0])
	if !ok {
		return starlark.None, fmt.Errorf("DLL name parameter must be a valid string")
	}

	procName, ok := starlark.AsString(args[1])
	if !ok {
		return starlark.None, fmt.Errorf("procedure name parameter must be a valid string")
	}

	proc := getLazyProc(dllName, procName)
	var uintptrArgs []uintptr
	var keepAlive []interface{}

	// Parse positional runtime variables into standard pointer layouts
	for i := 2; i < len(args); i++ {
		switch v := args[i].(type) {
		case starlark.Int:
			var uintptrVal uintptr
			if val, ok := v.Int64(); ok {
				uintptrVal = uintptr(val)
			} else if val, ok := v.Uint64(); ok {
				uintptrVal = uintptr(val)
			} else {
				return starlark.None, fmt.Errorf("failed parsing integer argument at index %d", i)
			}
			uintptrArgs = append(uintptrArgs, uintptrVal)
		case starlark.String:
			strVal := string(v)
			utf16Ptr := windows.StringToUTF16Ptr(strVal)
			uintptrArgs = append(uintptrArgs, uintptr(unsafe.Pointer(utf16Ptr)))
			keepAlive = append(keepAlive, utf16Ptr)
		case starlark.Bool:
			if bool(v) {
				uintptrArgs = append(uintptrArgs, 1)
			} else {
				uintptrArgs = append(uintptrArgs, 0)
			}
		case starlark.NoneType:
			uintptrArgs = append(uintptrArgs, 0)
		default:
			return starlark.None, fmt.Errorf("unsupported type parameter passed at index %d: %s", i, args[i].Type())
		}
	}

	initScriptVEH()
	scriptInWinCall = true
	defer func() {
		scriptInWinCall = false
	}()

	// Recover from dynamic procedure resolution panics or native VEH exceptions
	defer func() {
		if r := recover(); r != nil {
			dict := starlark.NewDict(4)
			dict.SetKey(starlark.String("r1"), starlark.MakeUint64(0))
			dict.SetKey(starlark.String("r2"), starlark.MakeUint64(0))
			dict.SetKey(starlark.String("error"), starlark.String(fmt.Sprintf("win_call error: %v", r)))
			dict.SetKey(starlark.String("err_code"), starlark.MakeUint64(1))
			retErr = nil
			retVal = dict
		}
	}()

	r1, r2, callErr := proc.Call(uintptrArgs...)
	_ = keepAlive

	dict := starlark.NewDict(4)
	dict.SetKey(starlark.String("r1"), starlark.MakeUint64(uint64(r1)))
	dict.SetKey(starlark.String("r2"), starlark.MakeUint64(uint64(r2)))

	errStr := ""
	var errCode uint64 = 0
	if callErr != nil && callErr != windows.ERROR_SUCCESS {
		errStr = callErr.Error()
		if errno, ok := callErr.(windows.Errno); ok {
			errCode = uint64(errno)
		}
	}
	dict.SetKey(starlark.String("error"), starlark.String(errStr))
	dict.SetKey(starlark.String("err_code"), starlark.MakeUint64(errCode))

	return dict, nil
}

// starlarkWinAlloc provides memory space via VirtualAlloc for data exchanges
func starlarkWinAlloc(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var size int
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "size", &size); err != nil {
		return starlark.None, err
	}
	if size <= 0 {
		return starlark.None, fmt.Errorf("allocation request size must be greater than zero")
	}

	addr, err := windows.VirtualAlloc(0, uintptr(size), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return starlark.None, fmt.Errorf("VirtualAlloc memory assignment failed: %w", err)
	}
	return starlark.MakeUint64(uint64(addr)), nil
}

// starlarkWinFree safely deallocates custom application pages via VirtualFree
func starlarkWinFree(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var addr uint64
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &addr); err != nil {
		return starlark.None, err
	}

	err := windows.VirtualFree(uintptr(addr), 0, windows.MEM_RELEASE)
	if err != nil {
		return starlark.None, fmt.Errorf("VirtualFree execution failed: %w", err)
	}
	return starlark.None, nil
}

// starlarkWinReadMem copies data out of unmanaged space back into a script list of bytes
func starlarkWinReadMem(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (retVal starlark.Value, retErr error) {
	var addr uint64
	var size int
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &addr, "size", &size); err != nil {
		return starlark.None, err
	}
	if size <= 0 {
		return starlark.None, fmt.Errorf("read range length constraint must be greater than zero")
	}
	if addr == 0 || addr < 4096 {
		return starlark.None, fmt.Errorf("win_read_mem: invalid memory address 0x%x", addr)
	}

	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("win_read_mem panic: %v", r)
		}
	}()

	buf := make([]byte, size)
	src := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(addr))), size)
	copy(buf, src)

	elems := make([]starlark.Value, size)
	for i, b := range buf {
		elems[i] = starlark.MakeInt(int(b))
	}
	return starlark.NewList(elems), nil
}
