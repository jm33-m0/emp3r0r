//go:build linux

package script

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
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

// withFakeSSHHarvest shadows the builtins ssh_harvest.star depends on and
// returns the supplied BPF events, so the module's orchestration and output
// formatting run against representative kernel data.
func withFakeSSHHarvest(t *testing.T, events []*starlark.Dict) {
	t.Helper()
	saved := make(map[string]StarlarkAPI)
	for _, name := range []string{"has_cap", "ebpf_code_offset", "ebpf_uprobe_capture"} {
		saved[name] = apis[name]
	}
	RegisterAPI("has_cap", func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
		return starlark.True, nil
	})
	RegisterAPI("ebpf_code_offset", func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
		d := starlark.NewDict(3)
		d.SetKey(starlark.String("offset"), starlark.MakeUint64(0x1234))
		d.SetKey(starlark.String("vaddr"), starlark.MakeUint64(0x401234))
		d.SetKey(starlark.String("error"), starlark.String(""))
		return d, nil
	})
	RegisterAPI("ebpf_uprobe_capture", func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
		list := starlark.NewList(nil)
		for _, ev := range events {
			list.Append(ev)
		}
		d := starlark.NewDict(2)
		d.SetKey(starlark.String("events"), list)
		d.SetKey(starlark.String("error"), starlark.String(""))
		return d, nil
	})
	t.Cleanup(func() {
		for name, fn := range saved {
			apis[name] = fn
		}
	})
}

func harvestEvent(pid int, retval int, comm, arg string) *starlark.Dict {
	d := starlark.NewDict(5)
	d.SetKey(starlark.String("pid"), starlark.MakeInt(pid))
	d.SetKey(starlark.String("uid"), starlark.MakeInt(0))
	d.SetKey(starlark.String("retval"), starlark.MakeInt(retval))
	d.SetKey(starlark.String("comm"), starlark.String(comm))
	d.SetKey(starlark.String("arg"), starlark.String(arg))
	return d
}

// TestSSHHarvestModule runs the real core/modules/ssh_harvest/ssh_harvest.star
// against fake uprobe events and checks the filtering and formatting it is
// responsible for: printable-only values, sshd-only comms, de-duplication, and
// the success annotation from the probed function's return value.
func TestSSHHarvestModule(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	starPath := filepath.Join(repoRoot, "modules", "ssh_harvest", "ssh_harvest.star")
	src, err := os.ReadFile(starPath)
	if err != nil {
		t.Fatalf("read ssh_harvest.star: %v", err)
	}

	// Seed a companion file so the module's BPF-object presence check passes;
	// the shadowed capture ignores the bytes.
	const memPath = "memfs:///ssh_harvest_test/probe.bpf.o"
	if err := util.WriteFileAgent(memPath, []byte("BPFfake-object"), 0o600); err != nil {
		t.Fatalf("seed memfs: %v", err)
	}
	defer util.RemoveFileAgent(memPath)

	events := []*starlark.Dict{
		harvestEvent(100, 1, "sshd", "supersecret"),
		harvestEvent(101, 0, "sshd", "wrongpass"),
		harvestEvent(100, 1, "sshd", "supersecret"), // duplicate
		harvestEvent(102, 1, "bash", "notssh"),      // wrong comm
		harvestEvent(103, 1, "sshd", "bin\x01ary"),  // non-printable
	}
	withFakeSSHHarvest(t, events)

	out, err := Run(src, []string{"RSI", "", "5", "/usr/sbin/sshd"}, map[string]any{
		"module_files": []string{memPath},
	}, 0)
	if err != nil {
		t.Fatalf("ssh_harvest run: %v\n%s", err, out)
	}

	for _, want := range []string{"supersecret", "wrongpass", "valid=yes", "valid=no", "0x1234", "2 credential(s) captured", "OK"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"notssh", "bin\x01ary"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("output leaked %q:\n%s", unwanted, out)
		}
	}
}

// TestSSHHarvestModuleGuards checks the module refuses to probe without the
// required capability or with an unknown register, before calling capture.
func TestSSHHarvestModuleGuards(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	src, err := os.ReadFile(filepath.Join(repoRoot, "modules", "ssh_harvest", "ssh_harvest.star"))
	if err != nil {
		t.Fatalf("read ssh_harvest.star: %v", err)
	}

	// No capability: capture must not be reached.
	saved := apis["has_cap"]
	t.Cleanup(func() { apis["has_cap"] = saved })
	RegisterAPI("has_cap", func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
		return starlark.False, nil
	})
	out, err := Run(src, []string{"RSI", "", "5", "/usr/sbin/sshd"}, nil, 0)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	if !strings.Contains(out, "CAP_BPF") {
		t.Fatalf("missing capability guard not reported:\n%s", out)
	}

	// Unknown register is rejected before any probe.
	withFakeSSHHarvest(t, nil)
	out, err = Run(src, []string{"RIP", "", "5", "/usr/sbin/sshd"}, nil, 0)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	if !strings.Contains(out, "unknown register") {
		t.Fatalf("unknown register not rejected:\n%s", out)
	}
}
