//go:build linux && cgo
// +build linux,cgo

package coffloader

import (
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
