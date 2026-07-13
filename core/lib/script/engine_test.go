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

func TestNewAPIs(t *testing.T) {
	script := `
def main(*args):
    # Test crypto_hash
    md5_hash = crypto_hash("md5", "hello")
    print("MD5 of hello: " + md5_hash)
    sha1_hash = crypto_hash("sha1", "hello")
    print("SHA1 of hello: " + sha1_hash)
    sha256_hash = crypto_hash("sha256", "hello")
    print("SHA256 of hello: " + sha256_hash)
    return "OK"
`
	out, err := Run([]byte(script), nil, nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if !strings.Contains(out, "MD5 of hello: 5d41402abc4b2a76b9719d911017c592") {
		t.Errorf("expected md5 match, got: %q", out)
	}
	if !strings.Contains(out, "SHA1 of hello: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d") {
		t.Errorf("expected sha1 match, got: %q", out)
	}
	if !strings.Contains(out, "SHA256 of hello: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824") {
		t.Errorf("expected sha256 match, got: %q", out)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("expected OK, got: %q", out)
	}

	if runtime.GOOS == "windows" {
		winScript := `
def main(*args):
    # Call GetTickCount64 from kernel32.dll
    res = win_call("kernel32.dll", "GetTickCount64")
    print("Ticks: " + str(res["r1"]))

    # Test win_alloc, GetLocalTime, win_read_mem, win_free
    addr = win_alloc(16)
    if addr == 0:
        return "Fail: alloc failed"
    win_call("kernel32.dll", "GetLocalTime", addr)
    year_bytes = win_read_mem(addr, 2)
    year = year_bytes[0] | (year_bytes[1] << 8)
    print("Year: " + str(year))
    win_free(addr)
    return "OK"
`
		out, err = Run([]byte(winScript), nil, nil)
		if err != nil {
			t.Fatalf("Run windows script failed: %v", err)
		}
		if !strings.Contains(out, "Ticks: ") {
			t.Errorf("expected ticks in output, got: %q", out)
		}
		if !strings.Contains(out, "Year: ") {
			t.Errorf("expected year in output, got: %q", out)
		}
		if !strings.Contains(out, "OK") {
			t.Errorf("expected OK from windows script, got: %q", out)
		}
	} else {
		// Non-Windows: verify win_* functions return errors
		nonWinScript := `
def main(*args):
    # win_call should fail
    res = win_call("kernel32.dll", "GetTickCount64")
    return "Fail: win_call succeeded on non-Windows"
`
		_, err = Run([]byte(nonWinScript), nil, nil)
		if err == nil {
			t.Errorf("expected error when calling win_call on non-Windows, but got none")
		} else if !strings.Contains(err.Error(), "win_call is only supported on Windows") {
			t.Errorf("expected 'win_call is only supported on Windows' error, got: %v", err)
		}

		nonWinScriptAlloc := `
def main(*args):
    # win_alloc should fail
    addr = win_alloc(16)
    return "Fail: win_alloc succeeded on non-Windows"
`
		_, err = Run([]byte(nonWinScriptAlloc), nil, nil)
		if err == nil {
			t.Errorf("expected error when calling win_alloc on non-Windows, but got none")
		} else if !strings.Contains(err.Error(), "win_alloc is only supported on Windows") {
			t.Errorf("expected 'win_alloc is only supported on Windows' error, got: %v", err)
		}
	}
}
