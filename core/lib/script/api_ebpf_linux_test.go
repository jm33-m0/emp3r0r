//go:build linux && !android && (386 || amd64 || arm64)

package script

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/memdeps"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
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
    w = ebpf_map_wipe(9)
    if w["error"] == "":
        return "fail: ebpf_map_wipe unexpectedly succeeded"
    if w["deleted"] != 0:
        return "fail: ebpf_map_wipe deleted entries alongside an error"
    off = ebpf_code_offset("/nonexistent-emp3r0r-path", "aabb")
    if off["error"] == "":
        return "fail: ebpf_code_offset unexpectedly succeeded"
    if off["offset"] != 0 or off["vaddr"] != 0:
        return "fail: ebpf_code_offset reported an address alongside an error"
    cap = ebpf_uprobe_capture(image="x", path="/bin/true", offset=0)
    if cap["error"] == "":
        return "fail: ebpf_uprobe_capture unexpectedly succeeded without libbpf"
    if len(cap["events"]) != 0:
        return "fail: ebpf_uprobe_capture returned events alongside an error"
    bad = ebpf_uprobe_capture(image="x", path="/bin/true", offset=0, reg="RIP")
    if bad["error"] == "":
        return "fail: ebpf_uprobe_capture accepted an unknown register"
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

// TestEBPFCodeOffsetReadsViaAgentIO proves ebpf_code_offset reads the ELF
// through the agent I/O layer: the image only exists in memfs, so a direct
// os.Open on the memfs:/// path would fail and the builtin would report an
// error.
func TestEBPFCodeOffsetReadsViaAgentIO(t *testing.T) {
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skip("zig not found in PATH")
	}

	const source = `
__attribute__((noinline, used)) int marker(int x) {
	__asm__ __volatile__(
		".byte 0x48,0x83,0xc4,0x08,0x0f,0xb6,0xc0,0x21,0x90\n"
	);
	return x + 1;
}
int main(void) { return marker(41) == 42 ? 0 : 1; }
`
	dir := t.TempDir()
	src := filepath.Join(dir, "marker.c")
	if err := os.WriteFile(src, []byte(source), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	out := filepath.Join(dir, "marker")
	cmd := exec.Command("zig", "cc", "-target", "x86_64-linux-gnu.2.17", "-O0", "-o", out, src)
	cmd.Env = append(os.Environ(),
		"ZIG_GLOBAL_CACHE_DIR="+filepath.Join(os.TempDir(), "emp3r0r-zig-global-cache"),
		"ZIG_LOCAL_CACHE_DIR="+filepath.Join(os.TempDir(), "emp3r0r-zig-local-cache"),
	)
	if buildOut, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("zig cc failed: %v\n%s", err, buildOut)
	}
	image, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}

	// The image is only available through memfs.
	memPath := "memfs:///ebpf_code_offset_io_test/marker"
	if err := util.WriteFileAgent(memPath, image, 0o600); err != nil {
		t.Fatalf("seed memfs: %v", err)
	}
	defer util.RemoveFileAgent(memPath)

	script := fmt.Sprintf(`
def main(*args):
    res = ebpf_code_offset(%q, "4883c4080fb6c02190")
    if res["error"] != "":
        return "fail: " + res["error"]
    if res["offset"] == 0:
        return "fail: offset not resolved from memfs image"
    if res["vaddr"] == 0:
        return "fail: vaddr not resolved from memfs image"
    return "OK"
`, memPath)
	outStr, err := Run([]byte(script), nil, nil, 0)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, outStr)
	}
	if !strings.Contains(outStr, "OK") {
		t.Fatalf("builtin did not resolve the memfs image:\n%s", outStr)
	}
}
