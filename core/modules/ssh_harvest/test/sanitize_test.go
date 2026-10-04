//go:build linux && !android && amd64

package sshharvesttest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestProbeObjectSanitized builds the BPF object with the toolchain the C2
// uses and checks the payload-sanitisation step ran. The object is uploaded to
// the agent, so it must not carry the build path (which names the module) or
// the probe source that clang embeds in .BTF/.BTF.ext.
func TestProbeObjectSanitized(t *testing.T) {
	for _, tool := range []string{"zig", "python3", "make"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found", tool)
		}
	}

	moduleDir := filepath.Join(repoRoot(t), "core", "modules", "ssh_harvest")
	buildDir := t.TempDir()
	for _, name := range []string{"probe.bpf.c", "Makefile", "sanitize_bpf.py"} {
		data, err := os.ReadFile(filepath.Join(moduleDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(buildDir, name), data, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	cmd := exec.Command("make")
	cmd.Dir = buildDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build probe.bpf.o: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(buildDir, "probe.bpf.o"))
	if err != nil {
		t.Fatalf("read probe.bpf.o: %v", err)
	}

	// Markers from the compiler's debug metadata: a source line, the helper the
	// probe calls and the absolute module directory.
	for _, marker := range []string{
		"regs[0] = ctx->ax;",
		"bpf_probe_read_user_str",
		moduleDir,
	} {
		if strings.Contains(string(raw), marker) {
			t.Errorf("shipped BPF object leaks %q", marker)
		}
	}
}
