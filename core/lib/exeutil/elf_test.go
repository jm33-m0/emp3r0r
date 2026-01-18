//go:build linux
// +build linux

package exeutil

import (
	"os"
	"testing"
)

// TestParseELFHeaders exercises ELF parsing helpers on a real system binary.
func TestParseELFHeaders(t *testing.T) {
	const bin = "/bin/echo"

	data, err := os.ReadFile(bin)
	if err != nil {
		t.Skipf("cannot read %s: %v", bin, err)
	}

	hdr, err := ParseELFHeaders(data)
	if err != nil {
		t.Fatalf("ParseELFHeaders failed: %v", err)
	}
	if hdr == nil || len(hdr.ProgramHeaders) == 0 {
		t.Fatalf("unexpected empty program headers for %s", bin)
	}

	if !IsELF(bin) {
		t.Fatalf("expected %s to be detected as ELF", bin)
	}
}
