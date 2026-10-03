//go:build linux && !android && (386 || amd64 || arm64)

package script

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/libbpf"
	"go.starlark.net/starlark"
)

// Starlark bindings for core/lib/libbpf. libbpf.so is mapped only for the
// duration of each builtin call and unmapped again as soon as it returns, so
// the dependency is never left resident in cleartext while the script that
// uses it is idle.
//
// Like sys_call, the builtins never abort a script on a runtime failure:
// they return a dict with the result and an "error" string (empty on success),
// so a module can report "libbpf unavailable" and continue.
func init() {
	RegisterAPI("ebpf_progs", starlarkEBPFProgs)
	RegisterAPI("ebpf_links", starlarkEBPFLinks)
	RegisterAPI("ebpf_maps", starlarkEBPFMaps)
	RegisterAPI("ebpf_detach", starlarkEBPFDetach)
	RegisterAPI("ebpf_map_wipe", starlarkEBPFMapWipe)
}

// ebpfCollect maps libbpf, runs collect to build the per-entry dicts, and
// returns the standard {"<key>": [...], "error": "..."} result. The library is
// unmapped before this returns.
func ebpfCollect(key string, collect func(*libbpf.Library) ([]starlark.Value, error)) *starlark.Dict {
	list := starlark.NewList(nil)
	err := libbpf.WithLibrary(func(lib *libbpf.Library) error {
		values, err := collect(lib)
		if err != nil {
			return err
		}
		for _, v := range values {
			list.Append(v)
		}
		return nil
	})
	return ebpfResult(key, list, err)
}

func starlarkEBPFProgs(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return ebpfCollect("progs", func(lib *libbpf.Library) ([]starlark.Value, error) {
		infos, err := lib.ProgList()
		if err != nil {
			return nil, err
		}
		out := make([]starlark.Value, 0, len(infos))
		for _, p := range infos {
			d := starlark.NewDict(6)
			d.SetKey(starlark.String("id"), starlark.MakeInt(int(p.ID)))
			d.SetKey(starlark.String("type"), starlark.MakeInt(int(p.Type)))
			d.SetKey(starlark.String("name"), starlark.String(p.Name))
			d.SetKey(starlark.String("load_time"), starlark.MakeUint64(p.LoadTime))
			d.SetKey(starlark.String("jited_len"), starlark.MakeInt(int(p.JitedLen)))
			d.SetKey(starlark.String("nr_maps"), starlark.MakeInt(int(p.NrMaps)))
			out = append(out, d)
		}
		return out, nil
	}), nil
}

func starlarkEBPFLinks(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return ebpfCollect("links", func(lib *libbpf.Library) ([]starlark.Value, error) {
		infos, err := lib.LinkList()
		if err != nil {
			return nil, err
		}
		out := make([]starlark.Value, 0, len(infos))
		for _, l := range infos {
			d := starlark.NewDict(4)
			d.SetKey(starlark.String("id"), starlark.MakeInt(int(l.ID)))
			d.SetKey(starlark.String("type"), starlark.MakeInt(int(l.Type)))
			d.SetKey(starlark.String("prog_id"), starlark.MakeInt(int(l.ProgID)))
			d.SetKey(starlark.String("prog_type"), starlark.MakeInt(int(l.ProgType)))
			out = append(out, d)
		}
		return out, nil
	}), nil
}

func starlarkEBPFMaps(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return ebpfCollect("maps", func(lib *libbpf.Library) ([]starlark.Value, error) {
		infos, err := lib.MapList()
		if err != nil {
			return nil, err
		}
		out := make([]starlark.Value, 0, len(infos))
		for _, m := range infos {
			d := starlark.NewDict(6)
			d.SetKey(starlark.String("id"), starlark.MakeInt(int(m.ID)))
			d.SetKey(starlark.String("type"), starlark.MakeInt(int(m.Type)))
			d.SetKey(starlark.String("name"), starlark.String(m.Name))
			d.SetKey(starlark.String("key_size"), starlark.MakeInt(int(m.KeySize)))
			d.SetKey(starlark.String("value_size"), starlark.MakeInt(int(m.ValueSize)))
			d.SetKey(starlark.String("max_entries"), starlark.MakeInt(int(m.MaxEntries)))
			out = append(out, d)
		}
		return out, nil
	}), nil
}

func starlarkEBPFDetach(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id int
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "id", &id); err != nil {
		return starlark.None, err
	}
	if id <= 0 {
		return starlark.None, fmt.Errorf("ebpf_detach: id must be positive")
	}
	err := libbpf.WithLibrary(func(lib *libbpf.Library) error {
		return lib.LinkDetach(uint32(id))
	})
	if err != nil {
		return ebpfErrorDict(err), nil
	}
	return ebpfResult("id", starlark.MakeInt(id), nil), nil
}

func starlarkEBPFMapWipe(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id int
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "id", &id); err != nil {
		return starlark.None, err
	}
	if id <= 0 {
		return starlark.None, fmt.Errorf("ebpf_map_wipe: id must be positive")
	}
	deleted := 0
	err := libbpf.WithLibrary(func(lib *libbpf.Library) error {
		n, e := lib.MapDeleteAll(uint32(id))
		deleted = n
		return e
	})
	d := ebpfResult("id", starlark.MakeInt(id), err)
	d.SetKey(starlark.String("deleted"), starlark.MakeInt(deleted))
	return d, nil
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
