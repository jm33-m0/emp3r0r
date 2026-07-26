//go:build !windows

package script

import (
	"fmt"

	"go.starlark.net/starlark"
)

func starlarkWinCall(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("win_call is only supported on Windows")
}

func starlarkWinAlloc(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("win_alloc is only supported on Windows")
}

func starlarkWinFree(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("win_free is only supported on Windows")
}

func starlarkWinReadMem(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("win_read_mem is only supported on Windows")
}

func readWinMem(_ uintptr, _ int) ([]byte, error) {
	return nil, fmt.Errorf("win_read_mem is only supported on Windows")
}
