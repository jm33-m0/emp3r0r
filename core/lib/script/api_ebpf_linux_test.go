//go:build linux && !android && (386 || amd64 || arm64)

package script

import (
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/memdeps"
)

// The ebpf_* builtins are backed by lib/libbpf. Without an agent-wired
// dependency resolver they must still be registered and return the result-dict
// shape with a non-empty "error" rather than an undefined-name failure.
func TestEBPFBuiltinsRegistered(t *testing.T) {
	skipUnderRace(t)
	memdeps.SetResolver(nil)
	defer memdeps.SetResolver(nil)

	script := `
def main(*args):
    for name in ("progs", "links", "maps"):
        fn = {"progs": ebpf_progs, "links": ebpf_links, "maps": ebpf_maps}[name]
        res = fn()
        if res["error"] == "":
            return "fail: ebpf_%s unexpectedly succeeded" % name
        if len(res[name]) != 0:
            return "fail: ebpf_%s returned data alongside an error" % name
    d = ebpf_detach(7)
    if d["error"] == "":
        return "fail: ebpf_detach unexpectedly succeeded"
    return "OK"
`
	out, err := Run([]byte(script), nil, nil, 0)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out, "OK") {
		t.Fatalf("unexpected output: %q", out)
	}
}
