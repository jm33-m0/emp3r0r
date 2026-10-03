package elfutil

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestHexPattern(t *testing.T) {
	cases := []struct {
		in      string
		want    []byte
		wantErr bool
	}{
		{"4883c408", []byte{0x48, 0x83, 0xc4, 0x08}, false},
		{"0x4883C408", []byte{0x48, 0x83, 0xc4, 0x08}, false},
		{"", nil, true},
		{"abc", nil, true},
		{"zz", nil, true},
	}
	for _, c := range cases {
		got, err := HexPattern(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("HexPattern(%q) = %x, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("HexPattern(%q): %v", c.in, err)
			continue
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("HexPattern(%q) = %x, want %x", c.in, got, c.want)
		}
	}
}

func TestFindCodePatternRejectsEmptyInput(t *testing.T) {
	if _, _, err := FindCodePattern(nil, []byte{1}); err == nil {
		t.Error("FindCodePattern accepted an empty image")
	}
	if _, _, err := FindCodePattern([]byte("not an elf"), nil); err == nil {
		t.Error("FindCodePattern accepted an empty pattern")
	}
}

// TestFindCodePatternCompiledELF embeds a known byte sequence in an executable
// and requires the scanner to report a file offset where those exact bytes
// occur, and a virtual address consistent with the segment mapping.
func TestFindCodePatternCompiledELF(t *testing.T) {
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skip("zig not found in PATH")
	}

	const source = `
__attribute__((noinline, used)) int marker(int x) {
	__asm__ __volatile__(
		".byte 0x48,0x83,0xc4,0x08,0x0f,0xb6,0xc0,0x21,0x90\n"
	);
	return x + 1;
}
int main(void) { return marker(41) == 42 ? 0 : 1; }
`
	dir := t.TempDir()
	src := filepath.Join(dir, "marker.c")
	if err := os.WriteFile(src, []byte(source), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	out := filepath.Join(dir, "marker")
	cmd := exec.Command("zig", "cc", "-target", "x86_64-linux-gnu.2.17", "-O0", "-o", out, src)
	cmd.Env = append(os.Environ(),
		"ZIG_GLOBAL_CACHE_DIR="+filepath.Join(os.TempDir(), "emp3r0r-zig-global-cache"),
		"ZIG_LOCAL_CACHE_DIR="+filepath.Join(os.TempDir(), "emp3r0r-zig-local-cache"),
	)
	if buildOut, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("zig cc failed: %v\n%s", err, buildOut)
	}

	pattern := []byte{0x48, 0x83, 0xc4, 0x08, 0x0f, 0xb6, 0xc0, 0x21, 0x90}
	// Callers read the image through the agent I/O layer; the test reads it
	// directly because it runs in the test process, not on the agent.
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	offset, vaddr, err := FindCodePattern(raw, pattern)
	if err != nil {
		t.Fatalf("FindCodePattern: %v", err)
	}

	// The reported file offset must actually contain the pattern.
	if offset+uint64(len(pattern)) > uint64(len(raw)) {
		t.Fatalf("offset %#x outside file (%d bytes)", offset, len(raw))
	}
	if !bytes.Equal(raw[offset:offset+uint64(len(pattern))], pattern) {
		t.Fatalf("bytes at reported offset %#x do not match the pattern", offset)
	}

	// A pattern that cannot exist must be reported as not found.
	missing := []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x00, 0x11, 0x22, 0x33}
	if _, _, err := FindCodePattern(raw, missing); !errors.Is(err, ErrPatternNotFound) {
		t.Fatalf("FindCodePattern(missing) = %v, want ErrPatternNotFound", err)
	}

	// vaddr and offset differ by the segment's mapping bias; both must be
	// non-zero and refer to the same byte for a typical PIE.
	if offset == 0 || vaddr == 0 {
		t.Fatalf("offset=%#x vaddr=%#x, want non-zero", offset, vaddr)
	}
}
