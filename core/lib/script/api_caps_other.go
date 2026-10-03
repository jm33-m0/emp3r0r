//go:build !linux

package script

import (
	"fmt"

	"go.starlark.net/starlark"
)

func init() {
	RegisterAPI("get_caps", starlarkGetCapsUnsupported)
	RegisterAPI("has_cap", starlarkHasCapUnsupported)
}

func starlarkGetCapsUnsupported(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("%s is only supported on Linux", fn.Name())
}

func starlarkHasCapUnsupported(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, fmt.Errorf("%s is only supported on Linux", fn.Name())
}
