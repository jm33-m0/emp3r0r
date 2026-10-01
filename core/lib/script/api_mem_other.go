//go:build !windows && !(linux && !android && (386 || amd64 || arm64))

package script

import (
	"fmt"

	"go.starlark.net/starlark"
)

// Stubs for platforms where core/lib/memmod has no loader backend. The
// builtins stay defined so scripts get a descriptive error instead of an
// undefined-name failure.

func init() {
	RegisterAPI("mem_load_library", starlarkMemLoadLibrary)
	RegisterAPI("mem_load", starlarkMemLoadLibrary)
	RegisterAPI("mem_proc_address", starlarkMemProcAddress)
	RegisterAPI("mem_proc_ordinal", starlarkMemProcOrdinal)
	RegisterAPI("mem_free", starlarkMemFree)
	RegisterAPI("mem_base_addr", starlarkMemBaseAddr)
}

func memLoadUnsupported(name string) error {
	return fmt.Errorf("%s is not supported on this platform", name)
}

func starlarkMemLoadLibrary(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, memLoadUnsupported(fn.Name())
}

func starlarkMemProcAddress(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, memLoadUnsupported(fn.Name())
}

func starlarkMemProcOrdinal(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, memLoadUnsupported(fn.Name())
}

func starlarkMemFree(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, memLoadUnsupported(fn.Name())
}

func starlarkMemBaseAddr(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, memLoadUnsupported(fn.Name())
}
