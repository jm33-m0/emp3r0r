package modules

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func compileProbeObject(t *testing.T, dir, target, name string) string {
	t.Helper()
	src := filepath.Join(dir, "probe.c")
	if err := os.WriteFile(src, []byte("int probe(void) { return 0; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, name)
	cmd := exec.Command("zig", "cc", "-target", target, "-c", "-o", out, src)
	if data, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile %s: %v\n%s", target, err, data)
	}
	return out
}

// TestRepairNativePayloadsDropsRiscvObjects checks that a payload left behind
// by a --riscv build is removed before native execution, while host objects and
// non-ELF files are left alone.
func TestRepairNativePayloadsDropsRiscvObjects(t *testing.T) {
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skip("zig not found")
	}
	dir := t.TempDir()
	rv := compileProbeObject(t, dir, "riscv32-linux-musl", "rv.o")
	host := compileProbeObject(t, dir, "x86_64-linux-gnu.2.17", "host.o")
	other := filepath.Join(dir, "other.o")
	if err := os.WriteFile(other, []byte("not an object"), 0o600); err != nil {
		t.Fatal(err)
	}

	config := &def.ModuleConfig{
		Name: "probe",
		Path: dir,
		AgentConfig: def.AgentModuleConfig{
			Files: []string{"rv.o", "host.o", "other.o"},
		},
	}
	repairNativePayloads(config)

	if _, err := os.Stat(rv); !os.IsNotExist(err) {
		t.Fatalf("RISC-V payload was kept: %v", err)
	}
	for _, keep := range []string{host, other} {
		if _, err := os.Stat(keep); err != nil {
			t.Fatalf("%s was removed: %v", keep, err)
		}
	}
}

// TestRepairNativePayloadsLeavesNativeModule verifies the repair is a no-op
// when every declared payload is a host object.
func TestRepairNativePayloadsLeavesNativeModule(t *testing.T) {
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skip("zig not found")
	}
	dir := t.TempDir()
	host := compileProbeObject(t, dir, "x86_64-linux-gnu.2.17", "host.o")
	config := &def.ModuleConfig{
		Name:        "probe",
		Path:        dir,
		AgentConfig: def.AgentModuleConfig{Files: []string{"host.o"}},
	}
	repairNativePayloads(config)
	if _, err := os.Stat(host); err != nil {
		t.Fatalf("native payload was removed: %v", err)
	}
}

// TestRepairNativePayloadsCleansMakeIntermediate verifies that a poisoned
// payload also triggers the module's make-based clean, so intermediates built
// for the other target cannot survive the repair.
func TestRepairNativePayloadsCleansMakeIntermediate(t *testing.T) {
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skip("zig not found")
	}
	newInstalledTestLayout(t)

	dir := t.TempDir()
	compileProbeObject(t, dir, "riscv32-linux-musl", "rv.o")
	intermediate := filepath.Join(dir, "intermediate.tmp")
	if err := os.WriteFile(intermediate, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	makefile := "clean:\n\trm -f intermediate.tmp\n"
	if err := os.WriteFile(filepath.Join(dir, "Makefile"), []byte(makefile), 0o600); err != nil {
		t.Fatal(err)
	}

	config := &def.ModuleConfig{
		Name:        "probe",
		Path:        dir,
		AgentConfig: def.AgentModuleConfig{Files: []string{"rv.o"}},
	}
	repairNativePayloads(config)
	if _, err := os.Stat(intermediate); !os.IsNotExist(err) {
		t.Fatalf("make clean did not run: %v", err)
	}
}
