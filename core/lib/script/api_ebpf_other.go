//go:build !(linux && !android && (386 || amd64 || arm64))

package script

import (
	"fmt"

	"go.starlark.net/starlark"
)

// ebpf_* builtins are backed by the in-memory libbpf loader, which is only
// available on Linux shared-object agents. They return the same result-dict
// shape as the real ones so scripts can stay platform-agnostic.
func init() {
	RegisterAPI("ebpf_progs", starlarkEBPFUnsupported)
	RegisterAPI("ebpf_links", starlarkEBPFUnsupported)
	RegisterAPI("ebpf_maps", starlarkEBPFUnsupported)
	RegisterAPI("ebpf_detach", starlarkEBPFUnsupported)
	RegisterAPI("ebpf_map_wipe", starlarkEBPFUnsupported)
}

var ebpfResultKeys = map[string]string{
	"ebpf_progs": "progs",
	"ebpf_links": "links",
	"ebpf_maps":  "maps",
}

func starlarkEBPFUnsupported(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	d := starlark.NewDict(3)
	if key, ok := ebpfResultKeys[fn.Name()]; ok {
		d.SetKey(starlark.String(key), starlark.NewList(nil))
	}
	if fn.Name() == "ebpf_map_wipe" {
		// Mirror the supported builtin's shape so scripts can read the same keys.
		d.SetKey(starlark.String("id"), starlark.MakeInt(0))
		d.SetKey(starlark.String("deleted"), starlark.MakeInt(0))
	}
	d.SetKey(starlark.String("error"), starlark.String(fmt.Sprintf("%s is only supported on Linux shared-object agents", fn.Name())))
	return d, nil
}
