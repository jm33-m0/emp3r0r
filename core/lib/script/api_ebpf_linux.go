//go:build linux && !android && (386 || amd64 || arm64)

package script

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/libbpf"
	"go.starlark.net/starlark"
)

// Starlark bindings for core/lib/libbpf. The library is loaded once, on first
// use, through the agent-wired fetcher (libbpf.SetFetcher).
//
// Like sys_call, the builtins never abort a script on a runtime failure:
// they return a dict with the result and an "error" string (empty on success),
// so a module can report "libbpf unavailable" and continue.
func init() {
	RegisterAPI("ebpf_progs", starlarkEBPFProgs)
	RegisterAPI("ebpf_links", starlarkEBPFLinks)
	RegisterAPI("ebpf_maps", starlarkEBPFMaps)
	RegisterAPI("ebpf_detach", starlarkEBPFDetach)
}

func starlarkEBPFProgs(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	progs := starlark.NewList(nil)
	lib, err := libbpf.Default()
	if err != nil {
		return ebpfResult("progs", progs, err), nil
	}
	list, err := lib.ProgList()
	if err != nil {
		return ebpfResult("progs", progs, err), nil
	}
	for _, p := range list {
		d := starlark.NewDict(4)
		d.SetKey(starlark.String("id"), starlark.MakeInt(int(p.ID)))
		d.SetKey(starlark.String("type"), starlark.MakeInt(int(p.Type)))
		d.SetKey(starlark.String("name"), starlark.String(p.Name))
		d.SetKey(starlark.String("load_time"), starlark.MakeUint64(p.LoadTime))
		progs.Append(d)
	}
	return ebpfResult("progs", progs, nil), nil
}

func starlarkEBPFLinks(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	links := starlark.NewList(nil)
	lib, err := libbpf.Default()
	if err != nil {
		return ebpfResult("links", links, err), nil
	}
	list, err := lib.LinkList()
	if err != nil {
		return ebpfResult("links", links, err), nil
	}
	for _, l := range list {
		d := starlark.NewDict(3)
		d.SetKey(starlark.String("id"), starlark.MakeInt(int(l.ID)))
		d.SetKey(starlark.String("type"), starlark.MakeInt(int(l.Type)))
		d.SetKey(starlark.String("prog_id"), starlark.MakeInt(int(l.ProgID)))
		links.Append(d)
	}
	return ebpfResult("links", links, nil), nil
}

func starlarkEBPFMaps(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	maps := starlark.NewList(nil)
	lib, err := libbpf.Default()
	if err != nil {
		return ebpfResult("maps", maps, err), nil
	}
	list, err := lib.MapList()
	if err != nil {
		return ebpfResult("maps", maps, err), nil
	}
	for _, m := range list {
		d := starlark.NewDict(6)
		d.SetKey(starlark.String("id"), starlark.MakeInt(int(m.ID)))
		d.SetKey(starlark.String("type"), starlark.MakeInt(int(m.Type)))
		d.SetKey(starlark.String("name"), starlark.String(m.Name))
		d.SetKey(starlark.String("key_size"), starlark.MakeInt(int(m.KeySize)))
		d.SetKey(starlark.String("value_size"), starlark.MakeInt(int(m.ValueSize)))
		d.SetKey(starlark.String("max_entries"), starlark.MakeInt(int(m.MaxEntries)))
		maps.Append(d)
	}
	return ebpfResult("maps", maps, nil), nil
}

func starlarkEBPFDetach(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id int
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "id", &id); err != nil {
		return starlark.None, err
	}
	if id <= 0 {
		return starlark.None, fmt.Errorf("ebpf_detach: id must be positive")
	}
	lib, err := libbpf.Default()
	if err != nil {
		return ebpfErrorDict(err), nil
	}
	if err := lib.LinkDetach(uint32(id)); err != nil {
		return ebpfErrorDict(err), nil
	}
	return ebpfResult("id", starlark.MakeInt(id), nil), nil
}

func ebpfErrorDict(err error) *starlark.Dict {
	d := starlark.NewDict(1)
	d.SetKey(starlark.String("error"), starlark.String(err.Error()))
	return d
}

func ebpfResult(key string, value starlark.Value, err error) *starlark.Dict {
	d := starlark.NewDict(2)
	d.SetKey(starlark.String(key), value)
	txt := ""
	if err != nil {
		txt = err.Error()
	}
	d.SetKey(starlark.String("error"), starlark.String(txt))
	return d
}
