//go:build linux

package script

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"go.starlark.net/starlark"
)

// capNames maps Linux capability numbers (bit positions) to their names, in
// order. The list follows include/uapi/linux/capability.h through
// CAP_CHECKPOINT_RESTORE (40).
var capNames = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_DAC_READ_SEARCH",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_KILL",
	"CAP_SETGID",
	"CAP_SETUID",
	"CAP_SETPCAP",
	"CAP_LINUX_IMMUTABLE",
	"CAP_NET_BIND_SERVICE",
	"CAP_NET_BROADCAST",
	"CAP_NET_ADMIN",
	"CAP_NET_RAW",
	"CAP_IPC_LOCK",
	"CAP_IPC_OWNER",
	"CAP_SYS_MODULE",
	"CAP_SYS_RAWIO",
	"CAP_SYS_CHROOT",
	"CAP_SYS_PTRACE",
	"CAP_SYS_PACCT",
	"CAP_SYS_ADMIN",
	"CAP_SYS_BOOT",
	"CAP_SYS_NICE",
	"CAP_SYS_RESOURCE",
	"CAP_SYS_TIME",
	"CAP_SYS_TTY_CONFIG",
	"CAP_MKNOD",
	"CAP_LEASE",
	"CAP_AUDIT_WRITE",
	"CAP_AUDIT_CONTROL",
	"CAP_SETFCAP",
	"CAP_MAC_OVERRIDE",
	"CAP_MAC_ADMIN",
	"CAP_SYSLOG",
	"CAP_WAKE_ALARM",
	"CAP_BLOCK_SUSPEND",
	"CAP_AUDIT_READ",
	"CAP_PERFMON",
	"CAP_BPF",
	"CAP_CHECKPOINT_RESTORE",
}

// capStatusKeys maps the /proc/self/status fields to the dict keys returned by
// get_caps.
var capStatusKeys = map[string]string{
	"CapInh": "inheritable",
	"CapPrm": "permitted",
	"CapEff": "effective",
	"CapBnd": "bounding",
	"CapAmb": "ambient",
}

func init() {
	RegisterAPI("get_caps", starlarkGetCaps)
	RegisterAPI("has_cap", starlarkHasCap)
}

// readCapMasks parses the Cap* bitmasks from /proc/self/status.
func readCapMasks() (map[string]uint64, error) {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil, fmt.Errorf("get_caps: read /proc/self/status: %w", err)
	}
	masks := make(map[string]uint64, len(capStatusKeys))
	for _, line := range strings.Split(string(status), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		set, wanted := capStatusKeys[strings.TrimSpace(key)]
		if !wanted {
			continue
		}
		mask, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
		if err != nil {
			return nil, fmt.Errorf("get_caps: parse %s: %w", key, err)
		}
		masks[set] = mask
	}
	return masks, nil
}

// setNames converts a capability bitmask into the list of capability names it
// contains.
func setNames(mask uint64) []string {
	names := make([]string, 0, 8)
	for i, name := range capNames {
		if mask&(uint64(1)<<uint(i)) != 0 {
			names = append(names, name)
		}
	}
	return names
}

// starlarkGetCaps returns the process capability sets as
// {inheritable, permitted, effective, bounding, ambient} lists of names.
func starlarkGetCaps(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs); err != nil {
		return starlark.None, err
	}
	masks, err := readCapMasks()
	if err != nil {
		return starlark.None, err
	}
	d := starlark.NewDict(len(masks))
	for set, mask := range masks {
		list := starlark.NewList(nil)
		for _, name := range setNames(mask) {
			list.Append(starlark.String(name))
		}
		d.SetKey(starlark.String(set), list)
	}
	return d, nil
}

// starlarkHasCap reports whether the named capability is in the effective set,
// so a script can attempt a privileged task when it is held and degrade when it
// is not.
func starlarkHasCap(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "cap", &name); err != nil {
		return starlark.None, err
	}
	name = strings.ToUpper(strings.TrimSpace(name))
	bit := -1
	for i, n := range capNames {
		if n == name {
			bit = i
			break
		}
	}
	if bit < 0 {
		return starlark.None, fmt.Errorf("has_cap: unknown capability %q", name)
	}
	masks, err := readCapMasks()
	if err != nil {
		return starlark.None, err
	}
	return starlark.Bool(masks["effective"]&(uint64(1)<<uint(bit)) != 0), nil
}
