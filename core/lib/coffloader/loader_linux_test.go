//go:build linux && cgo
// +build linux,cgo

package coffloader

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunLinuxCOFFWithInlineBOF(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("linux BOF loader test only supports amd64")
	}

	// Minimal BOF that matches the Beacon arg layout used by packLinuxArgs.
	const bofSrc = `#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char *buffer; int length; } datap;
static inline void BeaconDataParse(datap *parser, char *buffer, int size) { parser->buffer = buffer + 4; parser->length = size - 4; }
static inline int BeaconDataInt(datap *parser) { int32_t v = 0; if (parser->length >= 4) { memcpy(&v, parser->buffer, 4); parser->buffer += 4; parser->length -= 4; } return (int)v; }
static inline short BeaconDataShort(datap *parser) { int16_t v = 0; if (parser->length >= 2) { memcpy(&v, parser->buffer, 2); parser->buffer += 2; parser->length -= 2; } return (short)v; }
static inline char *BeaconDataExtract(datap *parser, int *size) { uint32_t len = 0; if (parser->length < 4) return NULL; memcpy(&len, parser->buffer, 4); parser->buffer += 4; char *out = parser->buffer; parser->buffer += len; parser->length -= (4 + len); if (size) *size = (int)len; return out; }
char *go(char *args, int size) { datap p; BeaconDataParse(&p, args, size); int id = BeaconDataInt(&p); short age = BeaconDataShort(&p); char *name = BeaconDataExtract(&p, NULL); char *buf = (char *)malloc(128); if (!buf) return NULL; snprintf(buf, 128, "[%d] Hello, %s (%d)!", id, name ? name : "", age); return buf; }`

	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "inline_bof.c")
	objPath := filepath.Join(tmpDir, "inline_bof.o")

	if err := os.WriteFile(srcPath, []byte(bofSrc), 0o600); err != nil {
		t.Fatalf("write BOF source: %v", err)
	}

	cmd := exec.Command("gcc", "-fPIC", "-c", srcPath, "-o", objPath)
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("gcc not available or failed to build inline BOF: %v, output: %s", err, string(out))
	}

	payload, err := os.ReadFile(objPath)
	if err != nil {
		t.Fatalf("read compiled object: %v", err)
	}

	args := []CoffArg{
		{WireType: "INT", Value: 1337},
		{WireType: "SHORT", Value: 25},
		{WireType: "LPSTR", Value: "Alice"},
	}

	out, err := RunLinuxCOFF(payload, "go", args)
	if err != nil {
		t.Fatalf("RunLinuxCOFF failed: %v", err)
	}

	if !strings.Contains(out, "Hello, Alice (25)!") || !strings.Contains(out, "[1337]") {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestHelloLinuxBOF(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("linux BOF loader test only supports amd64")
	}

	// Paths relative to core/lib/coffloader
	moduleDir := "../../modules/hello_linux"
	commonDir := "../../modules/bof_common"
	srcPath := filepath.Join(moduleDir, "hello_linux.c")

	if _, err := os.Stat(srcPath); os.IsNotExist(err) {
		t.Skipf("hello_linux module source not found at %s", srcPath)
	}

	tmpDir := t.TempDir()
	objPath := filepath.Join(tmpDir, "hello_linux.o")

	// Use gcc for tests as zig cc generates problematic code for the loader
	compiler := "gcc"
	args := []string{}
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not found")
	}

	args = append(args, "-fPIC", "-c", "-I"+commonDir, "-fno-stack-protector", "-fvisibility=hidden")
	args = append(args, srcPath, "-o", objPath)

	cmd := exec.Command(compiler, args...)
	cmd.Env = os.Environ()
	t.Logf("Compiling with: %s %v", compiler, args)

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("Compilation failed: %v\nOutput: %s", err, string(out))
	}

	payload, err := os.ReadFile(objPath)
	if err != nil {
		t.Fatalf("read compiled object: %v", err)
	}

	// Test case: Hello with Name
	t.Run("Greeting", func(t *testing.T) {
		args := []CoffArg{
			{WireType: "S", Value: "Unit Tester"},
		}
		out, err := RunLinuxCOFF(payload, "go", args)
		if err != nil {
			t.Fatalf("RunLinuxCOFF failed: %v", err)
		}
		t.Logf("Output: %s", out)
		if !strings.Contains(out, "Hello Unit Tester!") {
			t.Errorf("Unexpected output: %q", out)
		}
	})

	// Test case: Empty
	t.Run("Empty", func(t *testing.T) {
		args := []CoffArg{
			{WireType: "S", Value: ""},
		}
		out, err := RunLinuxCOFF(payload, "go", args)
		if err != nil {
			t.Fatalf("RunLinuxCOFF failed: %v", err)
		}
		t.Logf("Output: %s", out)
		if !strings.Contains(out, "Hello World!") {
			t.Errorf("Expected Hello World for empty input, got: %q", out)
		}
	})
}

func TestProcessListHandlesBOF(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("linux BOF loader test only supports amd64")
	}

	// Paths relative to core/lib/coffloader
	moduleDir := "../../modules/process_list_handles_linux"
	commonDir := "../../modules/bof_common"
	srcPath := filepath.Join(moduleDir, "process_list_handles_linux.c")

	if _, err := os.Stat(srcPath); os.IsNotExist(err) {
		t.Skipf("process_list_handles_linux module source not found at %s", srcPath)
	}

	tmpDir := t.TempDir()
	objPath := filepath.Join(tmpDir, "process_list_handles_linux.o")

	// Use gcc
	compiler := "gcc"
	args := []string{"-fPIC", "-c", "-I" + commonDir, "-fno-stack-protector", "-fvisibility=hidden", srcPath, "-o", objPath}

	cmd := exec.Command(compiler, args...)
	cmd.Env = os.Environ()
	t.Logf("Compiling with: %s %v", compiler, args)

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("Compilation failed: %v\nOutput: %s", err, string(out))
	}

	payload, err := os.ReadFile(objPath)
	if err != nil {
		t.Fatalf("read compiled object: %v", err)
	}

	// Test case: List handles for current process
	t.Run("CurrentProcess", func(t *testing.T) {
		pid := os.Getpid()
		args := []CoffArg{
			{WireType: "INT", Value: pid},
		}
		out, err := RunLinuxCOFF(payload, "go", args)
		if err != nil {
			t.Fatalf("RunLinuxCOFF failed: %v", err)
		}
		t.Logf("Output: %s", out)

		expectedHeader := fmt.Sprintf("Listing handles for PID %d", pid)
		if !strings.Contains(out, expectedHeader) {
			t.Errorf("Output missing expected header: %q", out)
		}
		// Expect to see some file descriptors, e.g., "0 ->", "1 ->", "2 ->"
		if !strings.Contains(out, " -> ") {
			t.Errorf("Output missing handle list: %q", out)
		}
	})
}
