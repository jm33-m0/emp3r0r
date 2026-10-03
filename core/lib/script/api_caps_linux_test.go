//go:build linux

package script

import (
	"strings"
	"testing"
)

// The get_caps/has_cap builtins must reflect the process's real effective set,
// so a privileged task can be attempted when the capability is held and
// skipped otherwise.
func TestGetCapsMatchesProcStatus(t *testing.T) {
	masks, err := readCapMasks()
	if err != nil {
		t.Fatalf("readCapMasks: %v", err)
	}
	want := strings.Join(setNames(masks["effective"]), ",")

	script := `
def main(*args):
    caps = get_caps()
    for set in ("inheritable", "permitted", "effective", "bounding", "ambient"):
        if set not in caps:
            return "missing set %s" % set
    eff = caps["effective"]
    for name in ("CAP_BPF", "CAP_SYS_ADMIN", "CAP_NET_RAW", "CAP_KILL", "CAP_SYS_MODULE"):
        if has_cap(name) != (name in eff):
            return "has_cap(%s) disagrees with effective set" % name
    return ",".join(eff)
`
	out, err := Run([]byte(script), nil, nil, 0)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := strings.TrimSpace(out); got != want {
		t.Fatalf("effective caps = %q, want %q", got, want)
	}
}

// An unknown capability name is a programming error and must be reported rather
// than silently treated as absent.
func TestHasCapUnknown(t *testing.T) {
	script := `
def main(*args):
    return has_cap("CAP_NOT_REAL")
`
	if _, err := Run([]byte(script), nil, nil, 0); err == nil {
		t.Fatal("has_cap accepted an unknown capability")
	}
}
