//go:build !linux

package script

import (
	"fmt"

	"go.starlark.net/starlark"
)

func starlarkSysCall(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("sys_call is only supported on Linux")
}

func starlarkSysAlloc(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("sys_alloc is only supported on Linux")
}

func starlarkSysFree(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("sys_free is only supported on Linux")
}

func starlarkSysReadMem(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("sys_read_mem is only supported on Linux")
}
