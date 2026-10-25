//go:build linux

package coffloader

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/lib/memdeps"
	"github.com/jm33-m0/emp3r0r/core/lib/memmod"
)

const linuxLoaderModule = "../../modules/coffloader_linux"

// wireLinuxLoader builds the coffloader_linux module and points the memdeps
// resolver at it, so RunLinuxCOFF maps the real loader just like the agent.
func wireLinuxLoader(t *testing.T) {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Skip("linux BOF loader test only supports amd64")
	}
	if os.Getenv("EMP3R0R_RACE_ON") == "1" {
		t.Skip("skipping: race detector checkptr conflicts with in-memory BOF execution")
	}
	if !memmod.LinuxLibcMapped() {
		t.Skip("Linux BOF tests need a dynamically linked agent with libc mapped")
	}
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skip("zig not found in PATH")
	}

	build := exec.Command("make", "-C", linuxLoaderModule)
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("building coffloader_linux: %v\n%s", err, out)
	}

	data, err := os.ReadFile(filepath.Join(linuxLoaderModule, "coffloader_linux.so"))
	if err != nil {
		t.Fatalf("read coffloader_linux.so: %v", err)
	}

	memdeps.SetResolver(func(name string) ([]byte, error) {
		if name != "coffloader_linux" {
			return nil, fmt.Errorf("unexpected dependency %q", name)
		}
		return data, nil
	})
	t.Cleanup(func() {
		memdeps.SetResolver(nil)
		clean := exec.Command("make", "-C", linuxLoaderModule, "clean")
		_ = clean.Run()
	})
}

// compileBOF builds a relocatable object from source with gcc. The loader is
// compiler-agnostic, but gcc's output is the most conservative object to
// exercise it with.
func compileBOF(t *testing.T, src string, includeDirs ...string) []byte {
	t.Helper()
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not found")
	}

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "bof.c")
	if err := os.WriteFile(srcPath, []byte(src), 0o600); err != nil {
		t.Fatalf("write BOF source: %v", err)
	}
	objPath := filepath.Join(dir, "bof.o")

	args := []string{"-fPIC", "-c", "-fno-stack-protector", "-fvisibility=hidden"}
	for _, inc := range includeDirs {
		args = append(args, "-I"+inc)
	}
	args = append(args, srcPath, "-o", objPath)

	cmd := exec.Command("gcc", args...)
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile BOF: %v\n%s", err, out)
	}
	payload, err := os.ReadFile(objPath)
	if err != nil {
		t.Fatalf("read BOF object: %v", err)
	}
	return payload
}

// TestRunLinuxCOFFWithInlineBOF runs a self-contained BOF through the real
// loader dependency and checks the Beacon argument round-trip.
func TestRunLinuxCOFFWithInlineBOF(t *testing.T) {
	wireLinuxLoader(t)

	const bofSrc = `#include <stdint.h>
#include <string.h>

typedef struct { char *buffer; int length; } datap;
static inline void BeaconDataParse(datap *parser, char *buffer, int size) { parser->buffer = buffer + 4; parser->length = size - 4; }
static inline int BeaconDataInt(datap *parser) { int32_t v = 0; if (parser->length >= 4) { memcpy(&v, parser->buffer, 4); parser->buffer += 4; parser->length -= 4; } return (int)v; }
static inline short BeaconDataShort(datap *parser) { int16_t v = 0; if (parser->length >= 2) { memcpy(&v, parser->buffer, 2); parser->buffer += 2; parser->length -= 2; } return (short)v; }
static inline char *BeaconDataExtract(datap *parser, int *size) { uint32_t len = 0; if (parser->length < 4) return 0; memcpy(&len, parser->buffer, 4); parser->buffer += 4; char *out = parser->buffer; parser->buffer += len; parser->length -= (4 + len); if (size) *size = (int)len; return out; }
extern void BeaconPrintf(int type, const char *fmt, ...);
void go(char *args, int size) { datap p; BeaconDataParse(&p, args, size); int id = BeaconDataInt(&p); short age = BeaconDataShort(&p); char *name = BeaconDataExtract(&p, 0); BeaconPrintf(0, "[%d] Hello, %s (%d)!", id, name ? name : "", age); }`

	payload := compileBOF(t, bofSrc)
	args := []CoffArg{
		{WireType: "INT", Value: 1337},
		{WireType: "SHORT", Value: 25},
		{WireType: "LPSTR", Value: "Alice"},
	}

	out, err := RunLinuxCOFF(payload, "go", args, 0)
	if err != nil {
		t.Fatalf("RunLinuxCOFF failed: %v", err)
	}
	if !strings.Contains(out, "Hello, Alice (25)!") || !strings.Contains(out, "[1337]") {
		t.Fatalf("unexpected output: %q", out)
	}
}

// TestBeaconFormatCompatibility drives the Beacon compatibility format API
// through a real BOF, including reset and bounded appends.
func TestBeaconFormatCompatibility(t *testing.T) {
	wireLinuxLoader(t)

	const src = `#include <stdint.h>
#include "beacon_api.h"
void go(char *args, int len) {
  (void)args;
  (void)len;
  formatp f;
  BeaconFormatAlloc(&f, 64);
  BeaconFormatAppend(&f, "hello", 5);
  BeaconFormatPrintf(&f, " %s %d", "world", 7);
  int n = 0;
  char *s = BeaconFormatToString(&f, &n);
  BeaconPrintf(CALLBACK_OUTPUT, "fmt=%s len=%d", s, n);
  BeaconFormatReset(&f);
  BeaconFormatAppend(&f, "x", 1);
  s = BeaconFormatToString(&f, &n);
  BeaconPrintf(CALLBACK_OUTPUT, " reset=%s len=%d", s, n);
  BeaconFormatFree(&f);
}`
	payload := compileBOF(t, src, "../../modules/SA_linux/includes")
	out, err := RunLinuxCOFF(payload, "go", nil, 0)
	if err != nil {
		t.Fatalf("RunLinuxCOFF(format): %v", err)
	}
	if !strings.Contains(out, "fmt=hello world 7 len=13") {
		t.Fatalf("format output = %q", out)
	}
	if !strings.Contains(out, "reset=x len=1") {
		t.Fatalf("format reset output = %q", out)
	}
}

// TestSALinuxBOF builds and runs one of the vendored TrustedSec SA Linux BOFs.
// It exercises the real libc symbol resolution path (uname/getOSName), not just
// the Beacon compatibility API.
func TestSALinuxBOF(t *testing.T) {
	wireLinuxLoader(t)

	moduleDir := "../../modules/SA_linux"
	if _, err := os.Stat(filepath.Join(moduleDir, "Makefile")); err != nil {
		t.Skipf("SA_linux module not found: %v", err)
	}
	build := exec.Command("make", "-C", moduleDir)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build SA_linux: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("make", "-C", moduleDir, "clean").Run()
	})

	payload, err := os.ReadFile(filepath.Join(moduleDir, "SA/src/uname.o"))
	if err != nil {
		t.Fatalf("read uname.o: %v", err)
	}
	out, err := RunLinuxCOFF(payload, "go", nil, 0)
	if err != nil {
		t.Fatalf("RunLinuxCOFF(uname): %v", err)
	}
	if !strings.Contains(out, "Linux") {
		t.Fatalf("uname output = %q, want Linux", out)
	}

	// env exercises the loader's getEnviron mock.
	payload, err = os.ReadFile(filepath.Join(moduleDir, "SA/src/env.o"))
	if err != nil {
		t.Fatalf("read env.o: %v", err)
	}
	out, err = RunLinuxCOFF(payload, "go", nil, 0)
	if err != nil {
		t.Fatalf("RunLinuxCOFF(env): %v", err)
	}
	if !strings.Contains(out, "PATH=") {
		t.Fatalf("env output = %q, want PATH", out)
	}
}

// TestHelloLinuxBOF runs the repository's Linux BOF module end to end.
func TestHelloLinuxBOF(t *testing.T) {
	wireLinuxLoader(t)

	srcPath := filepath.Join("../../modules/hello_linux", "hello_linux.c")
	src, err := os.ReadFile(srcPath)
	if err != nil {
		t.Skipf("hello_linux source not found: %v", err)
	}

	payload := compileBOF(t, string(src), "../../modules/bof_common")

	out, err := RunLinuxCOFF(payload, "go", []CoffArg{{WireType: "S", Value: "Unit Tester"}}, 0)
	if err != nil {
		t.Fatalf("RunLinuxCOFF failed: %v", err)
	}
	if !strings.Contains(out, "Hello Unit Tester!") {
		t.Fatalf("unexpected output: %q", out)
	}

	// An empty string must fall back to the default greeting; this exercises
	// the NUL-terminated packing (the BOF passes the pointer to %s).
	out, err = RunLinuxCOFF(payload, "go", []CoffArg{{WireType: "S", Value: ""}}, 0)
	if err != nil {
		t.Fatalf("RunLinuxCOFF failed: %v", err)
	}
	if !strings.Contains(out, "Hello World!") {
		t.Fatalf("expected default greeting, got: %q", out)
	}

	// A malformed object must fail cleanly rather than crash.
	if _, err := RunLinuxCOFF([]byte("\x7fELF\x02\x01\x01\x00garbage"), "go", nil, 0); err == nil {
		t.Fatal("expected an error for a malformed object")
	}
}

// TestRunLinuxCOFFStaticAgentError pins the diagnostic for a statically linked
// agent: it has no libc to bind the BOF loader against, so it must fail with a
// clear explanation instead of an unresolved-symbol dump.
func TestRunLinuxCOFFStaticAgentError(t *testing.T) {
	if memmod.LinuxLibcMapped() {
		t.Skip("agent is dynamically linked; the static-agent diagnostic does not apply")
	}
	_, err := RunLinuxCOFF([]byte("not an ELF object"), "go", nil, 0)
	if err == nil {
		t.Fatal("expected an error for a statically linked agent")
	}
	if !strings.Contains(err.Error(), "statically linked") || !strings.Contains(err.Error(), "libc") {
		t.Fatalf("error does not explain the static-agent limitation: %v", err)
	}
}
