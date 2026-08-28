//go:build !windows

package script

import (
	"fmt"

	"go.starlark.net/starlark"
)

// Non-Windows stubs for the core/lib/memmod bindings. memmod only exists on
// Windows, so these builtins fail with a descriptive error instead of being
// undefined.

func init() {
	RegisterAPI("mem_load_library", starlarkMemLoadLibrary)
	RegisterAPI("mem_load", starlarkMemLoadLibrary)
	RegisterAPI("mem_proc_address", starlarkMemProcAddress)
	RegisterAPI("mem_proc_ordinal", starlarkMemProcOrdinal)
	RegisterAPI("mem_free", starlarkMemFree)
	RegisterAPI("mem_base_addr", starlarkMemBaseAddr)
}

func starlarkMemLoadLibrary(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("mem_load_library is only supported on Windows")
}

func starlarkMemProcAddress(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("mem_proc_address is only supported on Windows")
}

func starlarkMemProcOrdinal(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("mem_proc_ordinal is only supported on Windows")
}

func starlarkMemFree(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("mem_free is only supported on Windows")
}

func starlarkMemBaseAddr(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("mem_base_addr is only supported on Windows")
}
