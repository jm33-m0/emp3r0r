package script

import (
	"strings"
	"testing"
)

func TestEngineRun(t *testing.T) {
	script := `
print("Hello from print statement!")
def main(*args):
    print("Inside main: " + ", ".join(argv))
    target = "test_starlark_write.txt"
    write_file(target, "Starlark was here")
    if not exists(target):
        return "Fail: file not written"
    content = read_file(target)
    if content != "Starlark was here":
        return "Fail: content mismatch: " + content
    files = list_dir(".")
    if target not in files:
        return "Fail: file not listed in list_dir"
    remove(target)
    if exists(target):
        return "Fail: file not removed"
    return "All tests in Starlark main passed"
`
	out, err := Run([]byte(script), []string{"arg1", "arg2"}, nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if !strings.Contains(out, "Hello from print statement!") {
		t.Errorf("expected output to contain print statement, got: %q", out)
	}
	if !strings.Contains(out, "Inside main: arg1, arg2") {
		t.Errorf("expected output to contain args, got: %q", out)
	}
	if !strings.Contains(out, "All tests in Starlark main passed") {
		t.Errorf("expected output to contain main return value, got: %q", out)
	}
}
