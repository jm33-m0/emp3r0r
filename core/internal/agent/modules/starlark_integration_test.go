package modules

import (
	"runtime"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func TestModuleHandler_Starlark_ProcessListing(t *testing.T) {
	script := `
def main(*args):
    procs = list_processes()
    if len(procs) == 0:
        print("Error: no processes found")
        return "FAIL"
    
    # Verify we can find some basic details
    found_self = False
    for p in procs:
        # Check if the process name looks like our test binary
        if "test" in p["name"].lower() or "go" in p["name"].lower():
            found_self = True
            print("Found test process: PID=" + str(p["pid"]) + ", Name=" + p["name"])
            break
            
    if found_self:
        print("Starlark integration process list success")
        return "OK"
    else:
        print("Starlark integration process list completed, but self not found")
        return "OK"
`
	if runtime.GOOS != "linux" {
		t.Skip("Process listing via /proc is only supported on Linux")
	}

	// Compress script content using helper in mod_test.go
	path, checksum := createTestModule(t, []byte(script))

	inv := def.ResolvedInvocation{
		Argv: []string{},
	}

	// Call ModuleHandler with "starlark" payload type
	out := ModuleHandler("", path, "starlark", "test_starlark_ps", checksum, inv)

	if !strings.Contains(out, "Starlark integration process list success") && !strings.Contains(out, "Starlark integration process list completed, but self not found") {
		t.Errorf("starlark output missing expected print logs: got %q", out)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("starlark output missing return value: got %q", out)
	}
}
