package modules

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

//go:embed rvguest/main.c
var rvGuestMain string

//go:embed rvguest/guest.ld
var rvGuestLinkerScript string

// linkRiscvPayloads turns each RV32 BOF object into a static musl executable.
// The executable carries libc, so BOF code uses the normal guest ABI instead of
// resolving every libc symbol through a host proxy.
func linkRiscvPayloads(config *def.ModuleConfig, env []string) error {
	if len(config.AgentConfig.Files) == 0 {
		return nil
	}
	dir, err := os.MkdirTemp("", "rvguest")
	if err != nil {
		return fmt.Errorf("create guest build dir: %w", err)
	}
	defer os.RemoveAll(dir)
	mainPath := filepath.Join(dir, "main.c")
	ldPath := filepath.Join(dir, "guest.ld")
	if err := os.WriteFile(mainPath, []byte(rvGuestMain), 0o600); err != nil {
		return fmt.Errorf("write guest entry: %w", err)
	}
	if err := os.WriteFile(ldPath, []byte(rvGuestLinkerScript), 0o600); err != nil {
		return fmt.Errorf("write guest linker script: %w", err)
	}

	seen := make(map[string]bool)
	for _, native := range config.AgentConfig.Files {
		if !strings.HasSuffix(strings.ToLower(native), ".o") {
			continue
		}
		if _, err := moduleFilePath(config.Path, native); err != nil {
			return err
		}
		rel := riscvPayloadPath(native)
		if seen[rel] {
			continue
		}
		seen[rel] = true
		out, err := moduleFilePath(config.Path, rel)
		if err != nil {
			return err
		}
		obj := strings.TrimSuffix(out, ".rv") + ".rv.o"
		if _, err := os.Stat(obj); err != nil {
			if _, outErr := os.Stat(out); outErr == nil {
				continue
			}
			return fmt.Errorf("RISC-V object %s: %w", obj, err)
		}
		args := []string{
			"build-exe",
			"-target", moduleRiscvTarget, "-mcpu=generic_rv32+a",
			"-static", "-O", "ReleaseSmall", "-fno-entry", "-fstrip", "-lc",
			"-T", ldPath, mainPath, obj, "-femit-bin=" + out,
		}
		for _, lib := range config.RiscvLibraries {
			if !strings.HasSuffix(lib, ".a") && !strings.HasSuffix(lib, ".o") {
				continue
			}
			libPath := lib
			if !filepath.IsAbs(libPath) {
				libPath = filepath.Join(config.Path, libPath)
			}
			if _, err := os.Stat(libPath); err != nil {
				return fmt.Errorf("RISC-V library %s: %w", lib, err)
			}
			args = append(args, libPath)
		}
		cmd := exec.Command("zig", args...)
		cmd.Dir = config.Path
		cmd.Env = env
		if data, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("link %s: %w\n%s", rel, err, data)
		}
	}
	return nil
}
