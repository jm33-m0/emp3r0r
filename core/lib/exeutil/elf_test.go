//go:build linux
// +build linux

package exeutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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

func TestInMemExeRun_StaticELF(t *testing.T) {
	if os.Getenv("CGO_ENABLED") != "1" {
		t.Skip("CGO not enabled")
	}
	if runtime.GOOS != "linux" {
		t.Skip("ELF loader is linux-specific")
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("ELF loader test currently only robust on amd64 in this environment")
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not found")
	}

	// 1. Compile a truly static PIE ELF
	srcFile := filepath.Join(t.TempDir(), "hello.c")
	binFile := filepath.Join(t.TempDir(), "hello")

	src := `
void _start() {
    const char msg[] = "hello elf\n";
    __asm__ __volatile__ (
        "mov $1, %%rax\n"
        "mov $1, %%rdi\n"
        "lea %0, %%rsi\n"
        "mov $10, %%rdx\n"
        "syscall\n"
        "mov $60, %%rax\n"
        "xor %%rdi, %%rdi\n"
        "syscall\n"
        : : "m"(msg) : "rax", "rdi", "rsi", "rdx"
    );
}
`
	if err := os.WriteFile(srcFile, []byte(src), 0o600); err != nil {
		t.Fatalf("write C src: %v", err)
	}

	// Try to compile as static-pie
	if _, err := exec.Command("gcc", "-nostdlib", "-static-pie", "-fPIE", srcFile, "-o", binFile).CombinedOutput(); err != nil {
		// Fallback to static if static-pie is not supported
		if out2, err2 := exec.Command("gcc", "-nostdlib", "-static", srcFile, "-o", binFile).CombinedOutput(); err2 != nil {
			t.Fatalf("compile static elf failed: %v, out: %s", err2, out2)
		}
	}
	elfData, err := os.ReadFile(binFile)
	if err != nil {
		t.Fatalf("read elf: %v", err)
	}
	if err != nil {
		t.Fatalf("read elf: %v", err)
	}

	out, err := InMemExeRun(elfData, []string{"elf_bin"}, os.Environ())
	if err != nil {
		t.Fatalf("InMemExeRun failed: %v", err)
	}

	if !strings.Contains(out, "hello elf") {
		t.Errorf("elf output mismatch: got %q", out)
	}
}
