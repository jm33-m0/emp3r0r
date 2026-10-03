//go:build linux

package script

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

// fakeEBPFResult builds the {key: [...], error: ""} shape the real ebpf_*
// builtins return.
func fakeEBPFResult(key string, entries []*starlark.Dict) *starlark.Dict {
	d := starlark.NewDict(2)
	list := starlark.NewList(nil)
	for _, e := range entries {
		list.Append(e)
	}
	d.SetKey(starlark.String(key), list)
	d.SetKey(starlark.String("error"), starlark.String(""))
	return d
}

// withFakeEBPF temporarily shadows the eBPF/capability builtins so the module
// formatting paths run with representative kernel data, then restores them.
func withFakeEBPF(t *testing.T, progs, links, maps []*starlark.Dict) {
	t.Helper()
	saved := make(map[string]StarlarkAPI)
	for _, name := range []string{"ebpf_progs", "ebpf_links", "ebpf_maps", "has_cap"} {
		saved[name] = apis[name]
	}
	RegisterAPI("ebpf_progs", func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
		return fakeEBPFResult("progs", progs), nil
	})
	RegisterAPI("ebpf_links", func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
		return fakeEBPFResult("links", links), nil
	})
	RegisterAPI("ebpf_maps", func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
		return fakeEBPFResult("maps", maps), nil
	})
	RegisterAPI("has_cap", func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
		return starlark.True, nil
	})
	t.Cleanup(func() {
		for name, fn := range saved {
			apis[name] = fn
		}
	})
}

// TestEBPFModuleFormatting runs the real edr_recon and tetragon_blind scripts
// against supplied BPF objects. It guards the sprintf format strings: the
// built-in % operator rejects flags/width and would abort the whole section.
func TestEBPFModuleFormatting(t *testing.T) {
	prog := starlark.NewDict(6)
	prog.SetKey(starlark.String("id"), starlark.MakeInt(7))
	prog.SetKey(starlark.String("type"), starlark.MakeInt(2)) // kprobe
	prog.SetKey(starlark.String("name"), starlark.String("falcon_probe"))
	prog.SetKey(starlark.String("load_time"), starlark.MakeUint64(1))
	prog.SetKey(starlark.String("jited_len"), starlark.MakeInt(123))
	prog.SetKey(starlark.String("nr_maps"), starlark.MakeInt(3))

	link := starlark.NewDict(4)
	link.SetKey(starlark.String("id"), starlark.MakeInt(8))
	link.SetKey(starlark.String("type"), starlark.MakeInt(2))
	link.SetKey(starlark.String("prog_id"), starlark.MakeInt(7))
	link.SetKey(starlark.String("prog_type"), starlark.MakeInt(2))

	bpfMap := starlark.NewDict(6)
	bpfMap.SetKey(starlark.String("id"), starlark.MakeInt(9))
	bpfMap.SetKey(starlark.String("type"), starlark.MakeInt(1)) // hash
	bpfMap.SetKey(starlark.String("name"), starlark.String("falcon_events"))
	bpfMap.SetKey(starlark.String("key_size"), starlark.MakeInt(4))
	bpfMap.SetKey(starlark.String("value_size"), starlark.MakeInt(8))
	bpfMap.SetKey(starlark.String("max_entries"), starlark.MakeInt(1024))

	withFakeEBPF(t, []*starlark.Dict{prog}, []*starlark.Dict{link}, []*starlark.Dict{bpfMap})

	_, filename, _, _ := runtime.Caller(0)
	modulesDir := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(filename))), "modules")
	for _, mod := range []struct {
		file   string
		action string
	}{
		{"linux_recon/edr_recon.star", "bpf,lsm"},
		{"linux_blind/tetragon_blind.star", "ebpf"},
	} {
		src, err := os.ReadFile(filepath.Join(modulesDir, mod.file))
		if err != nil {
			t.Fatalf("read %s: %v", mod.file, err)
		}
		out, err := Run(src, []string{mod.action}, nil, 0)
		if err != nil {
			t.Fatalf("%s %s failed: %v\n%s", mod.file, mod.action, err, out)
		}
		if !strings.Contains(out, "OK") {
			t.Fatalf("%s %s did not return OK:\n%s", mod.file, mod.action, out)
		}
		if strings.Contains(out, "%!") || strings.Contains(out, "unknown conversion") {
			t.Fatalf("%s %s produced a formatting error:\n%s", mod.file, mod.action, out)
		}
		if !strings.Contains(out, "falcon_probe") {
			t.Fatalf("%s %s did not report the supplied program:\n%s", mod.file, mod.action, out)
		}
	}
}
