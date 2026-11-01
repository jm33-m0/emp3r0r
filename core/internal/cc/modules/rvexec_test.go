package modules

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

func TestLinkRiscvPayloads(t *testing.T) {
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skip("zig not found")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "bof.c")
	if err := os.WriteFile(src, []byte("int go(char *a, int n){(void)a;(void)n;return 0;}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(dir, "bof.rv.o")
	cmd := exec.Command("zig", "cc", "-target", moduleRiscvTarget, "-mcpu=generic_rv32",
		"-O2", "-fno-pic", "-mno-relax", "-c", "-o", obj, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile RV32 object: %v\n%s", err, out)
	}
	config := def.ModuleConfig{
		Path:        dir,
		AgentConfig: def.AgentModuleConfig{Files: []string{"bof.o"}},
	}
	if err := linkRiscvPayloads(&config, os.Environ()); err != nil {
		t.Fatalf("link: %v", err)
	}
	checkLinkedGuest(t, filepath.Join(dir, "bof.rv"))
}

func TestLinkRiscvPayloadLibrary(t *testing.T) {
	if _, err := exec.LookPath("zig"); err != nil {
		t.Skip("zig not found")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bof.c"),
		[]byte("extern int answer(void); int go(char *a, int n){(void)a;(void)n;return answer();}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "libanswer.c"),
		[]byte("int answer(void){return 42;}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	compile := func(src, out string) {
		t.Helper()
		cmd := exec.Command("zig", "cc", "-target", moduleRiscvTarget, "-mcpu=generic_rv32",
			"-O2", "-fno-pic", "-mno-relax", "-c", "-o", out, src)
		if data, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("compile %s: %v\n%s", src, err, data)
		}
	}
	compile(filepath.Join(dir, "bof.c"), filepath.Join(dir, "bof.rv.o"))
	compile(filepath.Join(dir, "libanswer.c"), filepath.Join(dir, "libanswer.o"))
	config := def.ModuleConfig{
		Path:           dir,
		AgentConfig:    def.AgentModuleConfig{Files: []string{"bof.o"}},
		RiscvLibraries: []string{"libanswer.o"},
	}
	if err := linkRiscvPayloads(&config, os.Environ()); err != nil {
		t.Fatalf("link with library: %v", err)
	}
	checkLinkedGuest(t, filepath.Join(dir, "bof.rv"))
}

// checkLinkedGuest verifies the payload shape the interpreter expects and the
// artifact hygiene rules: a static RISC-V executable with the argument handoff
// section and no symbol tables.
func checkLinkedGuest(t *testing.T, path string) {
	t.Helper()
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("open linked executable: %v", err)
	}
	defer f.Close()
	if f.Type != elf.ET_EXEC || f.Machine != elf.EM_RISCV {
		t.Fatalf("linked type=%v machine=%v, want ET_EXEC RISC-V", f.Type, f.Machine)
	}
	if f.Section(".rvhdr") == nil {
		t.Fatal("linked payload has no argument handoff section")
	}
	for _, name := range []string{".symtab", ".strtab", ".comment"} {
		if f.Section(name) != nil {
			t.Fatalf("linked payload keeps %s", name)
		}
	}
}
