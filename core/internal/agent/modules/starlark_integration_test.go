package modules

import (
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func TestModuleHandler_Starlark(t *testing.T) {
	script := `
def main(*args):
    print("Starlark Module Handler Test Success")
    return "OK"
`
	// Compress script content using helper in mod_test.go
	path, checksum := createTestModule(t, []byte(script))

	inv := def.ResolvedInvocation{
		Argv: []string{"argA", "argB"},
	}

	// Call ModuleHandler with "starlark" payload type
	out := ModuleHandler("", path, "starlark", "test_starlark_module", checksum, inv)

	if !strings.Contains(out, "Starlark Module Handler Test Success") {
		t.Errorf("starlark output missing print: got %q", out)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("starlark output missing return value: got %q", out)
	}
}
