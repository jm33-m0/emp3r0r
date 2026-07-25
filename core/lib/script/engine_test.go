package script

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
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
    if "r1" not in res or "r2" not in res or "error" not in res or "err_code" not in res:
        return "Fail: missing error reporting keys in win_call return dict"
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

func TestRunStar(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	var scriptPath string
	if runtime.GOOS == "windows" {
		scriptPath = filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(filename))), "modules", "sa_starlark", "whoami.star")
	} else {
		scriptPath = filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(filename))), "modules", "starlark_procinfo", "run.star")
	}

	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		if os.IsNotExist(err) && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
			t.Skipf("skipping test on unsupported os %s", runtime.GOOS)
		}
		t.Fatalf("failed to read %s: %v", scriptPath, err)
	}

	out, err := Run(scriptBytes, nil, nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(out) == 0 {
		t.Errorf("expected script output, got empty")
	}
}

func TestLinuxSyscallAPIs(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("skipping Linux syscall test on %s", runtime.GOOS)
	}

	linuxScript := `
def main(*args):
    # Test getpid syscall by name and by sys_call
    res = sys_call("getpid")
    pid = res["r1"]
    if pid <= 0:
        return "Fail: invalid pid from sys_call"
    print("PID: " + str(pid))

    # Test lin_syscall alias
    res2 = lin_syscall("getpid")
    if res2["r1"] != pid:
        return "Fail: lin_syscall pid mismatch"

    # Test sys_alloc, sys_read_mem, sys_free
    addr = sys_alloc(64)
    if addr == 0:
        return "Fail: sys_alloc failed"

    mem = sys_read_mem(addr, 4)
    if len(mem) != 4:
        return "Fail: sys_read_mem failed"

    sys_free(addr)
    return "OK"
`
	out, err := Run([]byte(linuxScript), nil, nil)
	if err != nil {
		t.Fatalf("Run linux script failed: %v", err)
	}
	if !strings.Contains(out, "PID: ") {
		t.Errorf("expected PID in output, got: %q", out)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("expected OK from linux script, got: %q", out)
	}
}

func TestAllStarlarkModules(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	modulesDir := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(filename))), "modules")

	var starFiles []string
	err := filepath.Walk(modulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".star") {
			starFiles = append(starFiles, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk modules directory: %v", err)
	}

	if len(starFiles) == 0 {
		t.Fatalf("no .star files found in %s", modulesDir)
	}

	t.Logf("found %d starlark modules to test", len(starFiles))

	for _, path := range starFiles {
		relPath, _ := filepath.Rel(modulesDir, path)
		t.Run(relPath, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read %s: %v", path, err)
			}

			// 1. Validate syntax parsing on all platforms
			_, err = syntax.Parse(filepath.Base(path), data, 0)
			if err != nil {
				t.Fatalf("syntax error in %s: %v", path, err)
			}

			// 2. Execute script on supported platform
			if runtime.GOOS == "windows" && (strings.Contains(path, "priv_starlark") || strings.Contains(path, "sa_starlark")) {
				out, err := Run(data, []string{"1"}, nil)
				if err != nil {
					t.Errorf("error running %s on windows: %v", relPath, err)
				}
				t.Logf("output from %s:\n%s", relPath, out)
			} else if runtime.GOOS == "linux" && strings.Contains(path, "starlark_procinfo") {
				out, err := Run(data, nil, nil)
				if err != nil {
					t.Errorf("error running %s on linux: %v", relPath, err)
				}
				t.Logf("output from %s:\n%s", relPath, out)
			}
		})
	}
}

