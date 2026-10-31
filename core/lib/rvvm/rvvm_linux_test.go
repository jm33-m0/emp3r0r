//go:build linux

package rvvm

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

	build := exec.Command("make", "-C", moduleDir)
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("building rvvm: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		clean := exec.Command("make", "-C", moduleDir, "clean")
		_ = clean.Run()
	})

	data, err := os.ReadFile(filepath.Join(moduleDir, "rvvm_linux.so"))
	if err != nil {
		t.Fatalf("read rvvm_linux.so: %v", err)
	}

	// The interpreter serves host calls from libc and must not drag in any
	// other shared library.
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

	memdeps.SetResolver(func(name string) ([]byte, error) {
		if name != dependencyName() {
			return nil, fmt.Errorf("unexpected dependency %q", name)
		}
		return data, nil
	})
	t.Cleanup(func() { memdeps.SetResolver(nil) })
}

// buildBof compiles a BOF source as an RV32 ET_REL object, the only payload
// form the interpreter accepts.
func buildBof(t *testing.T, source string) []byte {
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
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read BOF: %v", err)
	}
	return data
}

// TestRunRiscvBof exercises the portable-BOF path: an RV32 relocatable object
// is relocated against the interpreter's embedded Beacon/libc runtime.
func TestRunRiscvBof(t *testing.T) {
	buildModule(t)

	bof := buildBof(t, `#include <string.h>
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
}`)
	out, err := RunRiscvBof(bof, "go", []coffloader.CoffArg{{WireType: "z", Value: "alpha"}}, nil)
	if err != nil {
		t.Fatalf("RunRiscvBof: %v", err)
	}
	if want := "bof alpha (6)\n"; out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}

	// No arguments: BeaconDataExtract returns NULL and the BOF still runs.
	out, err = RunRiscvBof(bof, "", nil, nil)
	if err != nil {
		t.Fatalf("RunRiscvBof(no args): %v", err)
	}
	if want := "bof (null) (0)\n"; out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}

	if _, err := RunRiscvBof(bof, "missing", nil, nil); err == nil || !strings.Contains(err.Error(), "BOF export not found") {
		t.Fatalf("missing export error = %v", err)
	}

	bad := buildBof(t, `extern void no_such_symbol(void);
int go(char *a, int l) { (void)a; (void)l; no_such_symbol(); return 0; }`)
	if _, err := RunRiscvBof(bad, "go", nil, nil); err == nil || !strings.Contains(err.Error(), "unresolved symbol no_such_symbol") {
		t.Fatalf("unresolved symbol error = %v", err)
	}

	// Windows BOF style import names (MODULE$Function) resolve to the same
	// guest runtime symbol, matching the COFFLoader convention.
	win := buildBof(t, `#include <string.h>
extern void BeaconPrintf(int, const char *, ...);
extern unsigned int KERNEL32$VirtualAlloc(unsigned int addr, unsigned int size, unsigned int type, unsigned int prot);
int go(char *a, int l) {
  (void)a; (void)l;
  unsigned int p = KERNEL32$VirtualAlloc(0, 16, 0x3000, 4);
  BeaconPrintf(0, "win %s", p ? "ok" : "no");
  return 0;
}`)
	if _, err := RunRiscvBof(win, "go", nil, nil); err != nil {
		t.Fatalf("Windows-style BOF imports: %v", err)
	}
}

// TestRunRiscvBofLibraries verifies that a delivered RISC-V library is loaded
// into guest RAM alongside the BOF and its symbols resolve across objects.
func TestRunRiscvBofLibraries(t *testing.T) {
	buildModule(t)

	lib := buildBof(t, `int answer(void) { return 42; }`)
	bof := buildBof(t, `#include <string.h>
extern int answer(void);
extern void BeaconPrintf(int, const char *, ...);
int go(char *a, int l) {
  (void)a; (void)l;
  BeaconPrintf(0, "lib %d", answer());
  return 0;
}`)
	out, err := RunRiscvBof(bof, "go", nil, [][]byte{lib})
	if err != nil {
		t.Fatalf("RunRiscvBof with library: %v", err)
	}
	if want := "lib 42\n"; out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
}
