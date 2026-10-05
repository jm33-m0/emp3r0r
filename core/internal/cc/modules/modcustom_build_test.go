package modules

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// TestShellQuote verifies the POSIX single-quote escaping used before
// interpolating module option values into the `sh -c` build command line.
// Every value must arrive as exactly one word, whatever shell metacharacters
// it contains.
func TestShellQuote(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"plain", "'plain'"},
		{"", "''"},
		{"two words", "'two words'"},
		{"it's", `'it'\''s'`},
		{"$(id)", "'$(id)'"},
		{"`id`; rm -rf /", "'`id`; rm -rf /'"},
		{"a'b'c", `'a'\''b'\''c'`},
		{"*?[]", "'*?[]'"},
		{"line1\nline2", "'line1\nline2'"},
	}
	for _, tt := range tests {
		if got := shellQuote(tt.in); got != tt.want {
			t.Errorf("shellQuote(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestBuildModuleShellQuotesFlags runs the real build_module() against a
// script that prints its argv verbatim, with option values full of shell
// metacharacters (command substitution, semicolons, single quotes, globs,
// spaces, empty). If any value were interpolated unquoted it would either
// execute the touch/echo and create the sentinel file, shift the argv, or
// glob-expand. The test asserts every value arrives as a single literal argv
// word and that nothing was executed.
func TestBuildModuleShellQuotesFlags(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("module build runs via sh, not available on windows")
	}

	modDir := t.TempDir()
	// Echo each argv entry on its own line so the output is order-preserving
	// and unambiguous even for empty values.
	echoArgs := filepath.Join(modDir, "echo_args.sh")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\"\n"
	if err := os.WriteFile(echoArgs, []byte(script), 0o700); err != nil {
		t.Fatalf("write echo_args.sh: %v", err)
	}

	// If any injection vector were executed, it would create its sentinel file.
	sentinelDir := t.TempDir()
	subSentinel := filepath.Join(sentinelDir, "pwned_sub")
	semiSentinel := filepath.Join(sentinelDir, "pwned_semi")

	// build_module chdirs into the module dir and back to live.EmpWorkSpace.
	// Restore the process working directory afterwards: leaving it inside a
	// temp dir that is removed at test end would break later tests (Getwd).
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	origWorkspace := live.EmpWorkSpace
	live.EmpWorkSpace = t.TempDir()
	defer func() {
		_ = os.Chdir(origWD)
		live.EmpWorkSpace = origWorkspace
	}()

	config := &def.ModuleConfig{Path: modDir, Build: "./echo_args.sh"}
	flags := map[string]string{
		"name":    "it's alive",
		"payload": "$(touch " + subSentinel + ")",
		"semi":    "; touch " + semiSentinel + "; #",
		"glob":    "*",
		"empty":   "",
	}
	out, err := build_module(config, flags)
	if err != nil {
		t.Fatalf("build_module: %v", err)
	}
	got := string(out)

	// Nothing may have executed: no sentinel may exist.
	for name, sentinel := range map[string]string{
		"command substitution": subSentinel,
		"semicolon injection":  semiSentinel,
	} {
		if _, statErr := os.Stat(sentinel); !os.IsNotExist(statErr) {
			t.Fatalf("%s executed: %s exists", name, sentinel)
		}
	}

	// Sorted flag order: empty, glob, name, payload, semi.
	wantLines := []string{
		"--empty",
		"", // empty value must survive as an empty word, not vanish
		"--glob",
		"*", // unquoted this would glob-expand against the module dir
		"--name",
		"it's alive", // single quote must not break out of the quoted word
		"--payload",
		"$(touch " + subSentinel + ")",
		"--semi",
		"; touch " + semiSentinel + "; #",
	}
	// Each arg prints on its own line, so require the exact sequence
	// (--flag line followed by value line).
	for i := 0; i+1 < len(wantLines); i += 2 {
		pair := wantLines[i] + "\n" + wantLines[i+1] + "\n"
		if !strings.Contains(got, pair) {
			t.Errorf("argv pair %q missing from build output:\n%s", pair, got)
		}
	}
}

// TestBuildModuleReturnsFailure is a regression test: a failing build must
// surface its error. The named return plus a deferred os.Chdir used to
// overwrite the build error with the (successful) chdir result, so a failed
// dependency build looked like success and the caller then failed with a
// confusing "no such file" while reading the missing payload.
func TestBuildModuleReturnsFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("module build runs via sh, not available on windows")
	}

	modDir := t.TempDir()
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	origWorkspace := live.EmpWorkSpace
	// build_module chdirs back to live.EmpWorkSpace; point it at the real cwd
	// so the process working directory is not left inside a deleted temp dir.
	live.EmpWorkSpace = origWD
	defer func() {
		_ = os.Chdir(origWD)
		live.EmpWorkSpace = origWorkspace
	}()

	config := &def.ModuleConfig{Path: modDir, Build: "echo boom >&2; exit 7"}
	_, err = build_module(config, nil)
	if err == nil {
		t.Fatal("build_module returned nil error for a failing build")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("build_module error %q does not include the build output", err)
	}
}

// TestEnsureModuleDependencyHostedSurfacesBuildFailure pins that a dependency
// whose build fails is reported as a build failure, not as a missing payload.
func TestEnsureModuleDependencyHostedSurfacesBuildFailure(t *testing.T) {
	origWWWRoot := live.WWWRoot
	origWorkspace := live.EmpWorkSpace
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	live.WWWRoot = t.TempDir()
	// build_module chdirs back to live.EmpWorkSpace; point it at the real cwd
	// so the process working directory is not left inside a deleted temp dir.
	live.EmpWorkSpace = origWD
	defer func() {
		_ = os.Chdir(origWD)
		live.WWWRoot = origWWWRoot
		live.EmpWorkSpace = origWorkspace
	}()

	dir := t.TempDir()
	def.Modules.Store("broken_dep", &def.ModuleConfig{
		Name:  "broken_dep",
		Path:  dir,
		Build: "echo dependency-build-failed >&2; exit 3",
		AgentConfig: def.AgentModuleConfig{
			Type:  "so",
			Files: []string{"broken_dep.so"},
		},
	})
	defer def.Modules.Delete("broken_dep")

	ctx := &context.C2Context{Target: &def.Emp3r0rAgent{GOOS: "linux", GOArch: "amd64"}}
	err = ensureModuleDependencyHosted(ctx, "broken_dep")
	if err == nil {
		t.Fatal("expected an error when the dependency build fails")
	}
	if !strings.Contains(err.Error(), "building dependency") {
		t.Fatalf("error %q does not identify the dependency build", err)
	}
	if !strings.Contains(err.Error(), "dependency-build-failed") {
		t.Fatalf("error %q does not include the build output", err)
	}
}
