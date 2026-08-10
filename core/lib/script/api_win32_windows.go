//go:build windows

package script

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"go.starlark.net/starlark"
	"golang.org/x/sys/windows"
)

var (
	dllCacheMu sync.RWMutex
	dllCache   = make(map[string]*windows.LazyDLL)
)

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

// callProcProtected is the implementation used to safely invoke a Win32
// DLL procedure.  It is set at init time by api_win32_veh_windows.go
// (VEH-based, catches all native exceptions).
var callProcProtected func(proc *windows.LazyProc, args ...uintptr) (r1, r2 uintptr, err error)

// starlarkWinCall provides an interface to execute any function within a specified DLL dynamically
func starlarkWinCall(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (retVal starlark.Value, retErr error) {
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

	// Recover from native access violations, dynamic procedure resolution panics,
	// and runtime call failures — all converted to a safe error dict.
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

	var r1, r2 uintptr
	var callErr error

	// Run the Win32 call under impersonation if a token is set.
	if err := runWithToken(thread, func() error {
		r1, r2, callErr = callProcProtected(proc, uintptrArgs...)
		return nil
	}); err != nil {
		// Impersonation failed — still call the API (as process identity)
		// but let the script know via the error key.
		thread.Print(thread, fmt.Sprintf("win_call: impersonation failed: %v", err))
		r1, r2, callErr = callProcProtected(proc, uintptrArgs...)
	}
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
func starlarkWinAlloc(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var size int
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "size", &size); err != nil {
		return starlark.None, err
	}
	if size <= 0 {
		return starlark.None, fmt.Errorf("allocation request size must be greater than zero")
	}

	var addr uintptr
	err := runWithToken(thread, func() error {
		var e error
		addr, e = windows.VirtualAlloc(0, uintptr(size), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
		return e
	})
	if err != nil {
		return starlark.None, fmt.Errorf("VirtualAlloc memory assignment failed: %w", err)
	}
	return starlark.MakeUint64(uint64(addr)), nil
}

// starlarkWinFree safely deallocates custom application pages via VirtualFree
func starlarkWinFree(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var addr uint64
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &addr); err != nil {
		return starlark.None, err
	}

	if addr == 0 {
		return starlark.None, nil
	}

	err := runWithToken(thread, func() error {
		return windows.VirtualFree(uintptr(addr), 0, windows.MEM_RELEASE)
	})
	if err != nil {
		return starlark.None, fmt.Errorf("VirtualFree execution failed: %w", err)
	}
	return starlark.None, nil
}

// starlarkWinReadMem copies data out of unmanaged space back into a script list of bytes safely via ReadProcessMemory
func starlarkWinReadMem(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (retVal starlark.Value, retErr error) {
	var addr uint64
	var size int
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &addr, "size", &size); err != nil {
		return starlark.None, err
	}
	if size < 0 {
		return starlark.None, fmt.Errorf("read range length constraint cannot be negative")
	}
	if size == 0 {
		return starlark.NewList(nil), nil
	}
	if addr == 0 || addr < 4096 {
		return starlark.None, fmt.Errorf("win_read_mem: unallocated or invalid memory address 0x%x", addr)
	}

	buf := make([]byte, size)
	var bytesRead uintptr
	var rpmErr error
	if err := runWithToken(thread, func() error {
		rpmErr = windows.ReadProcessMemory(windows.CurrentProcess(), uintptr(addr), &buf[0], uintptr(size), &bytesRead)
		return nil
	}); err != nil {
		thread.Print(thread, fmt.Sprintf("win_read_mem: impersonation failed: %v", err))
		rpmErr = windows.ReadProcessMemory(windows.CurrentProcess(), uintptr(addr), &buf[0], uintptr(size), &bytesRead)
	}
	if rpmErr != nil || bytesRead == 0 {
		return starlark.None, fmt.Errorf("win_read_mem: unallocated or invalid memory address 0x%x", addr)
	}

	buf = buf[:bytesRead]
	elems := make([]starlark.Value, len(buf))
	for i, b := range buf {
		elems[i] = starlark.MakeInt(int(b))
	}
	return starlark.NewList(elems), nil
}

func readWinMem(addr uintptr, size int) ([]byte, error) {
	buf := make([]byte, size)
	var bytesRead uintptr
	err := windows.ReadProcessMemory(windows.CurrentProcess(), addr, &buf[0], uintptr(size), &bytesRead)
	if err != nil || bytesRead == 0 {
		return nil, fmt.Errorf("readWinMem: invalid memory address 0x%x", addr)
	}
	return buf[:bytesRead], nil
}

// starlarkCurrentToken returns a handle to the current effective token.
// It tries OpenThreadToken first (so impersonation is visible), then falls
// back to OpenProcessToken. The caller must close the handle.
func starlarkCurrentToken(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if len(args) != 0 {
		return starlark.None, fmt.Errorf("current_token takes no arguments")
	}

	table := syscall.RuntimeSyscallTable
	if table == nil {
		return starlark.MakeUint64(0), nil
	}

	// If we have a stolen token in thread-local storage, duplicate a
	// query handle from it so the script can inspect the impersonated
	// identity.
	if tokenVal := thread.Local("token"); tokenVal != nil {
		if token, ok := tokenVal.(uintptr); ok && token != 0 {
			// Duplicate the token so the script gets its own handle.
			hDup, status, err := syscall.NtDuplicateToken(
				table,
				windows.Handle(token),
				windows.TOKEN_QUERY,
				nil,
				false,
				syscall.TokenImpersonation,
			)
			if err == nil && status == 0 && hDup != 0 {
				return starlark.MakeUint64(uint64(hDup)), nil
			}
		}
	}

	// No stolen token active — open the thread token (may be the process
	// identity if not impersonating, or fail if no thread token).
	var hToken windows.Handle
	if err := runWithToken(thread, func() error {
		h, status, err := syscall.NtOpenThreadToken(
			table,
			windows.CurrentThread(),
			windows.TOKEN_QUERY,
			false, // OpenAsSelf = FALSE: use thread identity
		)
		if err == nil && status == 0 {
			hToken = h
		}
		return nil
	}); err != nil {
		thread.Print(thread, fmt.Sprintf("current_token: NtOpenThreadToken: %v", err))
	}
	if hToken != 0 {
		return starlark.MakeUint64(uint64(hToken)), nil
	}

	// Fall back to process token.
	var hProcToken windows.Handle
	if err := runWithToken(thread, func() error {
		h, status, err := syscall.NtOpenProcessToken(
			table,
			windows.CurrentProcess(),
			windows.TOKEN_QUERY,
		)
		if err == nil && status == 0 {
			hProcToken = h
		}
		return nil
	}); err != nil {
		thread.Print(thread, fmt.Sprintf("current_token: NtOpenProcessToken: %v", err))
	}
	if hProcToken != 0 {
		return starlark.MakeUint64(uint64(hProcToken)), nil
	}

	return starlark.MakeUint64(0), nil
}
