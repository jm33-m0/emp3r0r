//go:build linux

package rvvm

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/coffloader"
	"github.com/jm33-m0/emp3r0r/core/lib/memdeps"
	"github.com/jm33-m0/emp3r0r/core/lib/memmod"
)

const (
	moduleDir = "../../modules/rvvm"
)

// buildModule builds the real rvvm module and points the memdeps resolver at
// it, so RunRiscvBof maps it exactly like the agent does.
func buildModule(t *testing.T) {
	t.Helper()
	buildModuleWith(t)
}

// buildModuleWith builds the module with extra make environment entries, which
// is how tests pin build-time limits such as the instruction budget.
func buildModuleWith(t *testing.T, env ...string) {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Skip("RISC-V BOF tests only support the amd64 build of the module")
	}
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("skipping: race detector checkptr conflicts with in-memory module calls")
	}
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skip("zig not found in PATH")
	}
	if !memmod.LinuxLibcMapped() {
		t.Skip("the interpreter links libc, so the test needs a dynamically linked process")
	}

	// Build in a private copy: the repository module directory is also read
	// by other test packages, and concurrent in-tree builds race with them.
	// The layout mirrors the operator workspace: modules/ and c_agent/ are
	// siblings, because the module Makefile includes ../../c_agent/include.
	root := t.TempDir()
	buildDir := filepath.Join(root, "modules", "rvvm")
	if err := os.MkdirAll(filepath.Dir(buildDir), 0o700); err != nil {
		t.Fatalf("create build tree: %v", err)
	}
	if err := os.CopyFS(buildDir, os.DirFS(moduleDir)); err != nil {
		t.Fatalf("copy rvvm module: %v", err)
	}
	if err := os.CopyFS(filepath.Join(root, "c_agent", "include"),
		os.DirFS("../../c_agent/include")); err != nil {
		t.Fatalf("copy shared includes: %v", err)
	}
	buildEnv := append(os.Environ(), env...)
	clean := exec.Command("make", "-C", buildDir, "clean")
	clean.Env = buildEnv
	_ = clean.Run()
	build := exec.Command("make", "-C", buildDir)
	build.Env = buildEnv
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building rvvm: %v\n%s", err, out)
	}

	data, err := os.ReadFile(filepath.Join(buildDir, "rvvm_linux.so"))
	if err != nil {
		t.Fatalf("read rvvm_linux.so: %v", err)
	}

	// The interpreter implements the syscall gate with libc and must not drag
	// in any other shared library.
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse rvvm_linux.so: %v", err)
	}
	libs, err := f.ImportedLibraries()
	if err != nil {
		t.Fatalf("imported libraries: %v", err)
	}
	for _, lib := range libs {
		if !strings.HasPrefix(lib, "libc.so") {
			t.Fatalf("rvvm_linux.so imports unexpected library %q", lib)
		}
	}
	_ = f.Close()

	memdeps.SetResolver(func(name, _ string) ([]byte, error) {
		if name != dependencyName() {
			return nil, fmt.Errorf("unexpected dependency %q", name)
		}
		return data, nil
	})
	t.Cleanup(func() { memdeps.SetResolver(nil) })
}

// buildBofObj compiles a BOF source as an RV32 object and returns the object
// path for tests that link it into a guest executable.
func buildBofObj(t *testing.T, source string) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "bof.c")
	if err := os.WriteFile(src, []byte(source), 0o600); err != nil {
		t.Fatalf("write BOF source: %v", err)
	}
	out := filepath.Join(dir, "bof.o")
	args := []string{
		"cc",
		"-target", "riscv32-linux-musl", "-mcpu=generic_rv32",
		"-O2", "-g0", "-fno-pic", "-mno-relax", "-msmall-data-limit=0",
		"-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
		"-fno-builtin", "-fno-stack-protector", "-fno-sanitize=all",
		"-fvisibility=hidden", "-c", "-o", out, src,
	}
	if b, err := exec.Command("zig", args...).CombinedOutput(); err != nil {
		t.Fatalf("building BOF: %v\n%s", err, b)
	}
	return out
}

// buildBof compiles a BOF source as an RV32 object and returns its bytes.
func buildBof(t *testing.T, source string) []byte {
	t.Helper()
	data, err := os.ReadFile(buildBofObj(t, source))
	if err != nil {
		t.Fatalf("read BOF: %v", err)
	}
	return data
}

// TestRunRiscvExec exercises the guest path: a static RV32 musl executable is
// loaded, musl starts, and the guest entry shim calls the BOF.
func TestRunRiscvExec(t *testing.T) {
	buildModule(t)

	img := linkRiscvExec(t, buildBofObj(t, `#include <string.h>
typedef struct { char *original; char *buffer; int length; int size; } datap;
extern void BeaconDataParse(datap *, char *, int);
extern char *BeaconDataExtract(datap *, int *);
extern void BeaconPrintf(int, const char *, ...);
int go(char *args, int len) {
  datap p;
  BeaconDataParse(&p, args, len);
  int n = 0;
  char *who = BeaconDataExtract(&p, &n);
  BeaconPrintf(0, "bof %s (%d)", who ? who : "(null)", n);
  return 0;
}`))
	out, err := RunRiscvBof(img, []coffloader.CoffArg{{WireType: "z", Value: "alpha"}})
	if err != nil {
		t.Fatalf("RunRiscvBof: %v", err)
	}
	if want := "bof alpha (6)\n"; out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}

	// No arguments: BeaconDataExtract returns NULL and the BOF still runs.
	out, err = RunRiscvBof(img, nil)
	if err != nil {
		t.Fatalf("RunRiscvBof(no args): %v", err)
	}
	if want := "bof (null) (0)\n"; out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
}

// linkRiscvExec links an RV32 BOF object with musl and the guest entry shim.
func linkRiscvExec(t *testing.T, obj string) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "bof.elf")
	cmd := exec.Command("zig", "build-exe",
		"-target", "riscv32-linux-musl", "-mcpu=generic_rv32+a",
		"-static", "-O", "ReleaseSmall", "-fno-entry", "-fstrip", "-lc",
		"-T", filepath.Join("..", "..", "internal", "cc", "modules", "rvguest", "guest.ld"),
		filepath.Join("..", "..", "internal", "cc", "modules", "rvguest", "main.c"),
		obj, "-femit-bin="+out)
	if data, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("link %s: %v\n%s", obj, err, data)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read %s: %v", out, err)
	}
	return data
}

// TestSALinuxBofsRiscvExec runs unmodified SA Linux BOFs as static RV32 musl
// executables. The guest starts at musl _start, initializes TLS and libc, then
// calls the BOF entry.
func TestSALinuxBofsRiscvExec(t *testing.T) {
	buildModule(t)
	t.Setenv("EMP3R0R_RVVM_ENV", "guest-visible")
	srcModule := filepath.Join("..", "..", "modules", "SA_linux")
	if _, err := os.Stat(filepath.Join(srcModule, "Makefile")); err != nil {
		t.Skipf("SA_linux not found: %v", err)
	}
	// Build in a private copy: other test packages also build this module.
	module := filepath.Join(t.TempDir(), "SA_linux")
	if err := os.CopyFS(module, os.DirFS(srcModule)); err != nil {
		t.Fatalf("copy SA_linux: %v", err)
	}
	_ = exec.Command("make", "-C", module, "clean").Run()
	if out, err := exec.Command("make", "-C", module).CombinedOutput(); err != nil {
		t.Fatalf("build SA_linux: %v\n%s", err, out)
	}

	for _, tc := range []struct {
		name string
		want string
		args []coffloader.CoffArg
	}{
		{"pwd", "/", nil},
		{"uname", "Linux", nil},
		{"id", "uid=", nil},
		{"whoami", "UID:", nil},
		{"env", "PATH=", nil},
		{"chmod", "Chmod", []coffloader.CoffArg{{WireType: "z", Value: "0755"}, {WireType: "z", Value: "/tmp"}}},
		{"cat", "root", []coffloader.CoffArg{{WireType: "z", Value: "/etc/passwd"}}},
		{"walk", "/etc", []coffloader.CoffArg{{WireType: "i", Value: "2"}, {WireType: "z", Value: "/etc"}}},
		{"find", "/etc/passwd", []coffloader.CoffArg{
			{WireType: "z", Value: "/etc"},
			{WireType: "z", Value: "passwd"},
			{WireType: "z", Value: ""},
			{WireType: "i", Value: "2"},
			{WireType: "i", Value: "0"},
			{WireType: "i", Value: "0"},
		}},
		{"tasklist", "systemd", nil},
		{"ifconfig", "IP Address", nil},
	} {
		img := linkRiscvExec(t, filepath.Join(module, "SA", "src", tc.name+".rv.o"))
		out, err := RunRiscvBof(img, tc.args)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !strings.Contains(out, tc.want) {
			t.Fatalf("%s output = %q, want %q", tc.name, out, tc.want)
		}
		if tc.name == "env" && !strings.Contains(out, "EMP3R0R_RVVM_ENV=guest-visible") {
			t.Fatalf("%s output = %q, want the agent environment", tc.name, out)
		}
		if tc.name == "tasklist" {
			// A full /proc scan must survive the guest output path; a stale
			// interpreter or a small output cap shows up as a short list.
			want := 0
			if entries, err := os.ReadDir("/proc"); err == nil {
				for _, e := range entries {
					if _, err := strconv.Atoi(e.Name()); err == nil {
						want++
					}
				}
			}
			if got := strings.Count(out, "\n"); got < want/2 {
				t.Fatalf("tasklist printed %d lines, want at least %d", got, want/2)
			}
		}
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hit.txt"), []byte("needle\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	img := linkRiscvExec(t, filepath.Join(module, "SA", "src", "grep.rv.o"))
	out, err := RunRiscvBof(img, []coffloader.CoffArg{
		{WireType: "z", Value: dir},
		{WireType: "z", Value: "needle"},
		{WireType: "z", Value: ""},
		{WireType: "i", Value: "2"},
		{WireType: "i", Value: "0"},
		{WireType: "i", Value: "0"},
	})
	if err != nil {
		t.Fatalf("grep: %v", err)
	}
	if !strings.Contains(out, "hit.txt") {
		t.Fatalf("grep output = %q, want hit.txt", out)
	}
}

// TestRiscvInstructionBudget checks the runaway-guest guard: a guest that never
// finishes is stopped and reported instead of wedging the job thread.
func TestRiscvInstructionBudget(t *testing.T) {
	buildModuleWith(t, "RV_MAX_INSNS=100000")
	img := linkRiscvExec(t, buildBofObj(t, `int go(char *a, int l) { (void)a; (void)l; for (;;) {} }`))
	_, err := RunRiscvBof(img, nil)
	if err == nil || !strings.Contains(err.Error(), "instruction budget exceeded") {
		t.Fatalf("spinning BOF error = %v", err)
	}
}

// TestRunRiscvExecRejectsBadImages verifies that the ET_EXEC loader validates
// the entry point, the program header table and every loadable segment.
func TestRunRiscvExecRejectsBadImages(t *testing.T) {
	buildModule(t)
	img := linkRiscvExec(t, buildBofObj(t, `int go(char *a, int l) { (void)a; (void)l; return 0; }`))

	if out, err := RunRiscvBof(img, nil); err != nil || out != "" {
		t.Fatalf("valid executable: out=%q err=%v", out, err)
	}

	le := binary.LittleEndian
	clone := func() []byte { return append([]byte(nil), img...) }

	bad := clone()
	le.PutUint32(bad[24:], 0) // e_entry
	if _, err := RunRiscvBof(bad, nil); err == nil || !strings.Contains(err.Error(), "bad executable entry point") {
		t.Fatalf("bad entry error = %v", err)
	}

	bad = clone()
	le.PutUint16(bad[44:], 0) // e_phnum
	if _, err := RunRiscvBof(bad, nil); err == nil || !strings.Contains(err.Error(), "bad program headers") {
		t.Fatalf("bad program header count error = %v", err)
	}

	bad = clone()
	phoff := int(le.Uint32(bad[28:]))
	phent := int(le.Uint16(bad[42:]))
	phnum := int(le.Uint16(bad[44:]))
	patched := false
	for i := 0; i < phnum; i++ {
		ph := phoff + i*phent
		if le.Uint32(bad[ph:]) == 1 { // PT_LOAD
			le.PutUint32(bad[ph+8:], 0x90000000) // p_vaddr outside guest RAM
			patched = true
			break
		}
	}
	if !patched {
		t.Fatal("linked executable has no PT_LOAD segment")
	}
	if _, err := RunRiscvBof(bad, nil); err == nil || !strings.Contains(err.Error(), "bad executable segment") {
		t.Fatalf("bad segment error = %v", err)
	}
}
