package script

import (
	"runtime"
	"strings"
	"testing"

	"go.starlark.net/starlark"
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

func TestEngineListProcesses(t *testing.T) {
	script := `
def main(*args):
    procs = list_processes()
    if len(procs) == 0:
        return "Fail: no processes found"
    
    # Check that each process has the expected keys
    first = procs[0]
    if "pid" not in first or "ppid" not in first or "name" not in first or "cmdline" not in first:
        return "Fail: missing keys in process dict"
    
    print("Found " + str(len(procs)) + " processes.")
    print("First process: PID=" + str(first["pid"]) + ", Name=" + first["name"])
    return "OK"
`
	out, err := Run([]byte(script), nil, nil)
	if runtime.GOOS != "linux" {
		if err == nil {
			t.Errorf("expected error on non-linux OS, but got none")
		}
		return
	}

	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("expected OK, got: %q", out)
	}
}

func TestEngineRegisterCustomAPI(t *testing.T) {
	// Register a new custom API function
	RegisterAPI("custom_multiply", func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var a, b int
		if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "a", &a, "b", &b); err != nil {
			return starlark.None, err
		}
		return starlark.MakeInt(a * b), nil
	})

	script := `
def main(*args):
    res = custom_multiply(6, 7)
    print("Result of multiplication is: " + str(res))
    return "OK"
`
	out, err := Run([]byte(script), nil, nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if !strings.Contains(out, "Result of multiplication is: 42") {
		t.Errorf("expected multiplication result 42, got output: %q", out)
	}
}
