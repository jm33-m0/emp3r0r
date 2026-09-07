package script

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// runExecCmdScript runs a starlark snippet that calls exec_cmd and returns
// the engine output plus error.
func runExecCmdScript(t *testing.T, src string) (string, error) {
	t.Helper()
	return Run([]byte(src), nil, nil, 0)
}

// TestExecCmdNoShellInterpolation verifies that exec_cmd passes each argument
// as its own argv entry to the child process and never routes the command line
// through a shell: values containing command substitution, semicolons,
// backticks or globs must arrive at the program as literal words and must not
// be executed.
func TestExecCmdNoShellInterpolation(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows CreateProcess command-line reconstruction differs (cmd
		// reparses batch files); the argv-passthrough property is asserted
		// for the POSIX path where exec_cmd is used with sh.
		t.Skip("argv-passthrough assertion is POSIX-specific")
	}

	// echo_args prints each argv entry on its own line, so argument order and
	// empty/whitespace values are observable and injection is detectable.
	dir := t.TempDir()
	script := filepath.Join(dir, "echo_args.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0o700); err != nil {
		t.Fatalf("write echo_args.sh: %v", err)
	}

	subSentinel := filepath.Join(t.TempDir(), "pwned_sub")
	semiSentinel := filepath.Join(t.TempDir(), "pwned_semi")

	payload := fmt.Sprintf(`$(touch %s)`, subSentinel)
	semi := fmt.Sprintf(`; touch %s; #`, semiSentinel)
	backtick := fmt.Sprintf("`touch %s`", semiSentinel)
	glob := "*"

	src := fmt.Sprintf(`
def main(*args):
    out = exec_cmd(%q, [%q, "--flag", %q, %q, %q, %q, ""])
    print(out)
    return "OK"
`, script, script, payload, semi, backtick, glob)

	out, err := runExecCmdScript(t, src)
	if err != nil {
		t.Fatalf("exec_cmd script failed: %v", err)
	}

	// Nothing may have executed through an injected metacharacter.
	for name, sentinel := range map[string]string{
		"command substitution": subSentinel,
		"semicolon injection":  semiSentinel,
	} {
		if _, statErr := os.Stat(sentinel); !os.IsNotExist(statErr) {
			t.Fatalf("%s executed: %s exists (output: %q)", name, sentinel, out)
		}
	}

	// print() echoes the raw child stdout: program (script path) first, then
	// "--flag" and every injected value, each on its own line, in order.
	want := []string{
		script,
		"--flag",
		payload,
		semi,
		backtick,
		glob,
		"", // empty trailing arg must still be passed
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < len(want) {
		t.Fatalf("expected at least %d argv lines, got %d:\n%s", len(want), len(lines), out)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q (full output:\n%s)", i, lines[i], want[i], out)
		}
	}
}

// TestExecCmdCapturesCombinedOutput verifies exec_cmd returns stdout and
// stderr combined, so scripts can surface child diagnostics.
func TestExecCmdCapturesCombinedOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("relies on POSIX sh")
	}
	out, err := runExecCmdScript(t, `
def main(*args):
    return exec_cmd("/bin/sh", ["-c", "printf out; printf err >&2"])
`)
	if err != nil {
		t.Fatalf("exec_cmd script failed: %v", err)
	}
	if !strings.Contains(out, "out") || !strings.Contains(out, "err") {
		t.Fatalf("expected combined stdout+stderr, got: %q", out)
	}
}

// TestExecCmdErrors verifies failure surfaces the command and error.
func TestExecCmdErrors(t *testing.T) {
	// Non-existent program.
	_, err := runExecCmdScript(t, `
def main(*args):
    exec_cmd("/definitely/not/a/real/binary", ["x"])
    return "Fail: expected error"
`)
	if err == nil {
		t.Fatal("expected error for missing binary, got none")
	}
	if !strings.Contains(err.Error(), "exec_cmd") {
		t.Fatalf("expected error to mention exec_cmd, got: %v", err)
	}

	// A non-string argv entry must be rejected during argument unpacking.
	_, err = runExecCmdScript(t, `
def main(*args):
    exec_cmd("sh", [1, 2, 3])
    return "Fail: expected type error"
`)
	if err == nil {
		t.Fatal("expected error for non-string argv, got none")
	}
	if !strings.Contains(err.Error(), "not a string") {
		t.Fatalf("expected argv type error, got: %v", err)
	}
}
