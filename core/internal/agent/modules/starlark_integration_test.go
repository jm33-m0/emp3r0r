package modules

import (
	"runtime"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func TestModuleHandler_Starlark_ProcInfo(t *testing.T) {
	script := `
def main(*args):
    cgroup = read_file("/proc/self/cgroup")
    if len(cgroup) == 0:
        print("Error: cgroup empty")
        return "FAIL"
    
    print("Starlark integration procinfo success")
    return "OK"
`
	if runtime.GOOS != "linux" {
		t.Skip("Procinfo via /proc is only supported on Linux")
	}

	// Compress script content using helper in mod_test.go
	path, checksum := createTestModule(t, []byte(script))

	inv := def.ResolvedInvocation{
		Argv: []string{},
	}

	// Call ModuleHandler with "starlark" payload type
	out := ModuleHandler("", path, "starlark", "test_starlark_procinfo", checksum, inv)

	if !strings.Contains(out, "Starlark integration procinfo success") {
		t.Errorf("starlark output missing expected print logs: got %q", out)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("starlark output missing return value: got %q", out)
	}
}
