package script

import (
	"encoding/json"
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
	out, err := Run([]byte(script), []string{"arg1", "arg2"}, nil, 0)
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
		out, err = Run([]byte(winScript), nil, nil, 0)
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
		_, err = Run([]byte(nonWinScript), nil, nil, 0)
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
		_, err = Run([]byte(nonWinScriptAlloc), nil, nil, 0)
		if err == nil {
			t.Errorf("expected error when calling win_alloc on non-Windows, but got none")
		} else if !strings.Contains(err.Error(), "win_alloc is only supported on Windows") {
			t.Errorf("expected 'win_alloc is only supported on Windows' error, got: %v", err)
		}
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
	out, err := Run([]byte(script), nil, nil, 0)
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
	out, err := Run([]byte(script), nil, nil, 0)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if !strings.Contains(out, "MD5 of hello: 5d41402abc4b2a76b9719d911017c592") {
		t.Errorf("unexpected md5 hash in output: %q", out)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("expected OK, got: %q", out)
	}
}

func TestStringAPIs(t *testing.T) {
	script := `
def main(*args):
    # Test sprintf & hex
    print("HEX: " + hex(255))
    print("FMT: " + sprintf("%04d-%02d-%02d %-10s", 2026, 7, 25, "test"))

    # Test str_split & str_join
    parts = str_split("a,b,c", ",")
    joined = str_join(parts, "-")
    print("JOINED: " + joined)

    # Test str_replace & str_contains
    replaced = str_replace("hello world", "world", "starlark")
    print("REPLACED: " + replaced)
    if not str_contains(replaced, "starlark"):
        return "Fail: str_contains failed"

    # Test str_trim, str_lower, str_upper
    trimmed = str_trim("  hello  ")
    print("TRIMMED: " + trimmed)
    print("LOWER: " + str_lower("HELLO"))
    print("UPPER: " + str_upper("hello"))

    # Test str_startswith, str_endswith, str_index
    if not str_startswith("hello", "he") or not str_endswith("hello", "lo"):
        return "Fail: prefix/suffix check failed"
    if str_index("hello", "ll") != 2:
        return "Fail: str_index failed"

    # Test pad
    print("PAD: [" + pad("foo", 8) + "]")
    return "OK"
`
	out, err := Run([]byte(script), nil, nil, 0)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if !strings.Contains(out, "HEX: 0xff") {
		t.Errorf("expected HEX: 0xff, got: %q", out)
	}
	if !strings.Contains(out, "FMT: 2026-07-25 test      ") {
		t.Errorf("expected FMT: 2026-07-25 test      , got: %q", out)
	}
	if !strings.Contains(out, "JOINED: a-b-c") {
		t.Errorf("expected JOINED: a-b-c, got: %q", out)
	}
	if !strings.Contains(out, "REPLACED: hello starlark") {
		t.Errorf("expected REPLACED: hello starlark, got: %q", out)
	}
	if !strings.Contains(out, "PAD: [foo     ]") {
		t.Errorf("expected PAD: [foo     ], got: %q", out)
	}
}

func TestMemHelperAPIs(t *testing.T) {
	var script string
	if runtime.GOOS == "windows" {
		script = `
def main(*args):
    addr = win_alloc(64)
    if addr == 0:
        return "Fail: alloc failed"
    
    write_u8(addr, 0, 0x12)
    write_u16(addr, 2, 0x1234)
    write_u32(addr, 4, 0xDEADBEEF)
    write_u64(addr, 8, 0x1122334455667788)

    v8 = read_u8(addr, 0)
    v16 = read_u16(addr, 2)
    v32 = read_u32(addr, 4)
    v64 = read_u64(addr, 8)

    print("V8: " + hex(v8))
    print("V16: " + hex(v16))
    print("V32: " + hex(v32))
    print("V64: " + hex(v64))

    u_ptr = utf16_ptr("Hello WString")
    ws = read_wstring(u_ptr)
    print("WSTRING: " + ws)
    win_free(u_ptr)

    c_ptr = cstring_ptr("Hello CString")
    cs = read_cstring(c_ptr)
    print("CSTRING: " + cs)
    win_free(c_ptr)

    win_free(addr)
    return "OK"
`
	} else {
		script = `
def main(*args):
    addr = sys_alloc(64)
    if addr == 0:
        return "Fail: alloc failed"
    
    write_u8(addr, 0, 0x12)
    write_u16(addr, 2, 0x1234)
    write_u32(addr, 4, 0xDEADBEEF)
    write_u64(addr, 8, 0x1122334455667788)

    v8 = read_u8(addr, 0)
    v16 = read_u16(addr, 2)
    v32 = read_u32(addr, 4)
    v64 = read_u64(addr, 8)

    print("V8: " + hex(v8))
    print("V16: " + hex(v16))
    print("V32: " + hex(v32))
    print("V64: " + hex(v64))

    u_ptr = utf16_ptr("Hello WString")
    ws = read_wstring(u_ptr)
    print("WSTRING: " + ws)
    sys_free(u_ptr)

    c_ptr = cstring_ptr("Hello CString")
    cs = read_cstring(c_ptr)
    print("CSTRING: " + cs)
    sys_free(c_ptr)

    sys_free(addr)
    return "OK"
`
	}

	out, err := Run([]byte(script), nil, nil, 0)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if !strings.Contains(out, "V8: 0x12") {
		t.Errorf("expected V8: 0x12, got: %q", out)
	}
	if !strings.Contains(out, "V16: 0x1234") {
		t.Errorf("expected V16: 0x1234, got: %q", out)
	}
	if !strings.Contains(out, "V32: 0xdeadbeef") {
		t.Errorf("expected V32: 0xdeadbeef, got: %q", out)
	}
	if !strings.Contains(out, "V64: 0x1122334455667788") {
		t.Errorf("expected V64: 0x1122334455667788, got: %q", out)
	}
	if !strings.Contains(out, "WSTRING: Hello WString") {
		t.Errorf("expected WSTRING: Hello WString, got: %q", out)
	}
	if !strings.Contains(out, "CSTRING: Hello CString") {
		t.Errorf("expected CSTRING: Hello CString, got: %q", out)
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
	out, err := Run([]byte(linuxScript), nil, nil, 0)
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

func TestPanicRecovery(t *testing.T) {
	// Test 1: Top-level panic recovery in script.Run
	customGlobals := map[string]any{
		"trigger_panic": starlark.NewBuiltin("trigger_panic", func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			panic("simulated builtin panic")
		}),
	}

	panicScript := `
def main(*args):
    print("before panic")
    trigger_panic()
    print("after panic")
    return "OK"
`
	out, err := Run([]byte(panicScript), nil, customGlobals, 0)
	if err == nil {
		t.Fatalf("expected error from panic recovery, got nil")
	}
	if !strings.Contains(err.Error(), "script engine panic") || !strings.Contains(err.Error(), "simulated builtin panic") {
		t.Errorf("expected 'script engine panic: simulated builtin panic' error, got: %v", err)
	}
	if !strings.Contains(out, "before panic") {
		t.Errorf("expected output buffer to contain 'before panic', got: %q", out)
	}

	// Test 2: FFI invalid memory read recovery on Linux
	if runtime.GOOS == "linux" {
		memPanicScript := `
def main(*args):
    res = sys_read_mem(0xDEADBEEF00000000, 16)
    return "OK"
`
		_, err := Run([]byte(memPanicScript), nil, nil, 0)
		if err == nil {
			t.Errorf("expected error when reading invalid memory address on Linux, got nil")
		} else if !strings.Contains(err.Error(), "unallocated or invalid memory address") {
			t.Errorf("expected 'unallocated or invalid memory address' error, got: %v", err)
		}

		nullMemScript := `
def main(*args):
    res = sys_read_mem(0, 16)
    return "OK"
`
		_, err = Run([]byte(nullMemScript), nil, nil, 0)
		if err == nil {
			t.Errorf("expected error when reading NULL address on Linux, got nil")
		} else if !strings.Contains(err.Error(), "unallocated or invalid memory address") {
			t.Errorf("expected 'unallocated or invalid memory address' error, got: %v", err)
		}
	}

	// Test 3: FFI invalid memory read recovery on Windows
	if runtime.GOOS == "windows" {
		winMemPanicScript := `
def main(*args):
    res = win_read_mem(0xDEADBEEF00000000, 16)
    return "OK"
`
		_, err := Run([]byte(winMemPanicScript), nil, nil, 0)
		if err == nil {
			t.Errorf("expected error when reading invalid memory address on Windows, got nil")
		} else if !strings.Contains(err.Error(), "unallocated or invalid memory address") {
			t.Errorf("expected 'unallocated or invalid memory address' error, got: %v", err)
		}

		winNullMemScript := `
def main(*args):
    res = win_read_mem(0, 16)
    return "OK"
`
		_, err = Run([]byte(winNullMemScript), nil, nil, 0)
		if err == nil {
			t.Errorf("expected error when reading NULL address on Windows, got nil")
		} else if !strings.Contains(err.Error(), "unallocated or invalid memory address") {
			t.Errorf("expected 'unallocated or invalid memory address' error, got: %v", err)
		}
	}
}

type moduleConfigEntry struct {
	Platform    string `json:"platform"`
	AgentConfig struct {
		Exec  string   `json:"exec"`
		Files []string `json:"files"`
		Type  string   `json:"type"`
	} `json:"agent_config"`
}

func getStarlarkScriptPlatform(starPath string) string {
	dir := filepath.Dir(starPath)
	configPath := filepath.Join(dir, "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}

	var entries []moduleConfigEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		var single moduleConfigEntry
		if errSingle := json.Unmarshal(data, &single); errSingle == nil {
			entries = []moduleConfigEntry{single}
		} else {
			return ""
		}
	}

	starBase := filepath.Base(starPath)
	for _, entry := range entries {
		if entry.AgentConfig.Exec == starBase {
			return strings.ToLower(entry.Platform)
		}
		for _, f := range entry.AgentConfig.Files {
			if filepath.Base(f) == starBase {
				return strings.ToLower(entry.Platform)
			}
		}
	}
	return ""
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

			// 2. Execute script on supported platform determined dynamically from config.json
			platform := getStarlarkScriptPlatform(path)
			shouldRun := platform == "" || platform == "any" || platform == "all" || platform == runtime.GOOS

			if shouldRun {
				out, err := Run(data, []string{"1"}, nil, 0)
				if err != nil {
					t.Errorf("error running %s on %s: %v", relPath, runtime.GOOS, err)
				}
				t.Logf("output from %s:\n%s", relPath, out)
			}
		})
	}
}

func TestAgentProxyAPIs(t *testing.T) {
	origProxy := GetAgentProxy()
	defer SetAgentProxy(origProxy)
	SetAgentProxy(&testMockAgentProxy{})

	script := `
def main(*args):
    # Test agent.sys_info() and agent_sys_info()
    info = agent.sys_info()
    if "goos" not in info or "user" not in info or "cwd" not in info:
        return "Fail: missing sys_info keys"
    
    info2 = agent_sys_info()
    if info2["goos"] != info["goos"]:
        return "Fail: agent_sys_info mismatch"

    # Test uptime
    up = agent.uptime()
    if agent_uptime() != up:
        return "Fail: agent_uptime mismatch"
    print("Uptime: " + up)

    # Test user & groups
    user_info = agent.user()
    if "user" not in user_info or "groups" not in user_info:
        return "Fail: agent.user missing keys"

    # Test container check
    container = agent.container()
    print("Container: " + container)

    # Test root check
    is_root = agent.has_root()
    if agent_has_root() != is_root or agent_is_root() != is_root or agent.is_root() != is_root:
        return "Fail: root status mismatch"
    print("IsRoot: " + str(is_root))

    # Test exec_shell
    out = agent.exec_shell("echo hello_agent_proxy")
    if "hello_agent_proxy" not in out:
        return "Fail: exec_shell output mismatch: " + out
    
    out2 = agent_exec_shell("echo hello_top_level")
    if "hello_top_level" not in out2:
        return "Fail: agent_exec_shell output mismatch: " + out2

    return "OK"
`
	out, err := Run([]byte(script), nil, nil, 0)
	if err != nil {
		t.Fatalf("Run agent proxy script failed: %v", err)
	}
	if !strings.Contains(out, "Uptime: ") || !strings.Contains(out, "OK") {
		t.Errorf("expected Uptime and OK in output, got: %q", out)
	}
}

type testMockAgentProxy struct{}

func (m *testMockAgentProxy) GatherSystemDetails() (map[string]any, error) {
	return map[string]any{
		"goos": "linux",
		"user": "testuser",
		"cwd":  "/tmp",
	}, nil
}

func (m *testMockAgentProxy) GetUptime() string {
	return "mocked 100 days"
}

func (m *testMockAgentProxy) GetUserAndGroups() (string, string) {
	return "testuser", "testgroup"
}

func (m *testMockAgentProxy) GetContainerName() string {
	return "none"
}

func (m *testMockAgentProxy) HasRoot() bool {
	return false
}

func (m *testMockAgentProxy) ExecuteShell(scriptBytes []byte, argv, env []string) (string, error) {
	return "mock shell: " + string(scriptBytes), nil
}

func (m *testMockAgentProxy) ExecutePython(scriptBytes []byte, argv, env []string) (string, error) {
	return "mock python: " + string(scriptBytes), nil
}

func (m *testMockAgentProxy) ExecutePowerShell(scriptBytes []byte, argv, env []string) (string, error) {
	return "mock powershell: " + string(scriptBytes), nil
}

func (m *testMockAgentProxy) ExecuteBatch(scriptBytes []byte, argv, env []string) (string, error) {
	return "mock batch: " + string(scriptBytes), nil
}

func (m *testMockAgentProxy) SignWithAgentKey(data []byte) ([]byte, error) {
	return append([]byte("SIGNED:"), data...), nil
}

func (m *testMockAgentProxy) GetTag() string {
	return "test-agent-tag"
}

func (m *testMockAgentProxy) GetUUID() string {
	return "test-agent-uuid"
}

func (m *testMockAgentProxy) TouchFile(path string) error {
	return nil
}

func (m *testMockAgentProxy) CopyFileTimes(src, dst string) error {
	return nil
}

func (m *testMockAgentProxy) FetchFile(peer, fileToDownload, path, checksum string) ([]byte, error) {
	if path != "" {
		return nil, nil
	}
	return []byte("fetched:" + fileToDownload), nil
}

func TestCustomAgentProxy(t *testing.T) {
	origProxy := GetAgentProxy()
	defer SetAgentProxy(origProxy)

	SetAgentProxy(&testMockAgentProxy{})

	script := `
def main(*args):
    up = agent.uptime()
    if up != "mocked 100 days":
        return "Fail: custom uptime expected 'mocked 100 days', got: " + up

    tag = agent.tag()
    if tag != "test-agent-tag":
        return "Fail: custom tag mismatch: " + tag

    uuid = agent.uuid()
    if uuid != "test-agent-uuid":
        return "Fail: custom uuid mismatch: " + uuid

    sig = agent.sign("hello")
    if str(sig) != "SIGNED:hello":
        return "Fail: custom sign mismatch: " + str(sig)

    sh = agent.exec_shell("echo hello_agent_proxy")
    if sh != "mock shell: echo hello_agent_proxy":
        return "Fail: custom exec_shell mismatch: " + sh

    fetched = agent.fetch_file("test.bin")
    if str(fetched) != "fetched:test.bin":
        return "Fail: custom fetch_file mismatch: " + str(fetched)

    return "OK"
`
	out, err := Run([]byte(script), nil, nil, 0)
	if err != nil {
		t.Fatalf("Run custom agent proxy script failed: %v", err)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("expected OK from custom proxy script, got: %q", out)
	}
}

