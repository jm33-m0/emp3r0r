package modules

import (
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// payloadIsRiscv reports whether path is an ELF object built for RISC-V.
// A Windows COFF object (or a missing/garbage file) is not reported.
func payloadIsRiscv(path string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return f.Machine == elf.EM_RISCV
}

// repairNativePayloads removes native payloads that a previous --riscv build
// overwrote with RISC-V objects, and cleans make-based intermediates from the
// same build. The next native build therefore compiles from source with the
// host toolchain instead of reusing the other target's objects.
// moduleFilePath joins a module-relative payload path and rejects absolute
// paths and traversal. A module manifest must not be able to point the repair
// step at a file outside its own directory.
func moduleFilePath(dir, rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) || !filepath.IsLocal(rel) ||
		strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, `\`) ||
		filepath.VolumeName(rel) != "" {
		return "", fmt.Errorf("invalid module payload path %q", rel)
	}
	clean := filepath.Clean(rel)
	if clean == "." || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid module payload path %q", rel)
	}
	path := filepath.Join(dir, clean)
	inside, err := filepath.Rel(dir, path)
	if err != nil || inside == ".." ||
		strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("module payload path %q escapes %s", rel, dir)
	}
	return path, nil
}

func repairNativePayloads(config *def.ModuleConfig) {
	if config == nil {
		return
	}
	poisoned := false
	for _, file := range config.AgentConfig.Files {
		path, err := moduleFilePath(config.Path, file)
		if err != nil {
			logging.Warningf("%s: %v", config.Name, err)
			continue
		}
		if !payloadIsRiscv(path) {
			continue
		}
		logging.Warningf("%s: dropping %s: a previous --riscv build left a RISC-V object there",
			config.Name, file)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			logging.Warningf("%s: remove %s: %v", config.Name, file, err)
			continue
		}
		poisoned = true
	}
	if !poisoned || !hasMakefile(config.Path) {
		return
	}

	// The same build compiled every source for RISC-V, so intermediates can be
	// poisoned too. A make-based module removes them deterministically; if the
	// clean fails, the payload removal above still forces a rebuild.
	env, err := moduleBuildEnv()
	if err != nil {
		logging.Warningf("%s: clean RISC-V build output: %v", config.Name, err)
		return
	}
	cmd := exec.Command("make", "clean")
	cmd.Dir = config.Path
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		logging.Warningf("%s: make clean after a RISC-V build: %v\n%s",
			config.Name, err, out)
	}
}

func hasMakefile(dir string) bool {
	for _, name := range []string{"GNUmakefile", "Makefile", "makefile"} {
		if util.IsFileExist(filepath.Join(dir, name)) {
			return true
		}
	}
	return false
}
