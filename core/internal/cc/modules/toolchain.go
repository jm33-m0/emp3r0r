package modules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

const moduleToolchainSubdir = ".module-toolchain"

var moduleToolchainMu sync.Mutex

// moduleLinuxTarget is the zig triple for the C2 host's Linux ABI. Buildable
// modules run on the C2 or are loaded by a Linux agent on the same host, so
// they are pinned to the oldest glibc ABI the project supports.
func moduleLinuxTarget() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64-linux-gnu.2.17", nil
	case "386":
		return "x86-linux-gnu.2.17", nil
	case "arm64":
		return "aarch64-linux-gnu.2.17", nil
	case "arm":
		return "arm-linux-gnueabihf.2.17", nil
	case "riscv64":
		// Zig has no glibc 2.17 target for riscv64; musl has a stable ABI.
		return "riscv64-linux-musl", nil
	default:
		return "", fmt.Errorf("unsupported Linux module architecture: %s", runtime.GOARCH)
	}
}

// findModuleZig prefers the zig toolchain shipped in the installed tree, then
// falls back to PATH for source-tree builds and tests.
func findModuleZig() (string, error) {
	candidates := []string{filepath.Join(live.EmpDataDir, "zig", "zig"), "zig"}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if resolved, err := exec.LookPath(candidate); err == nil {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("zig not found in the installed toolchain or PATH")
}

// ensureModuleToolchain writes compiler shims into the workspace and returns
// their directory. Module Makefiles hardcode names such as gcc, clang or
// x86_64-w64-mingw32-gcc, so putting these shims first on PATH makes every
// module build use the shipped zig regardless of its Makefile.
func ensureModuleToolchain() (string, string, error) {
	if runtime.GOOS != "linux" {
		return "", "", fmt.Errorf("module builds require Linux")
	}
	if live.EmpWorkSpace == "" {
		return "", "", fmt.Errorf("operator workspace is not initialized")
	}
	linuxTarget, err := moduleLinuxTarget()
	if err != nil {
		return "", "", err
	}
	zig, err := findModuleZig()
	if err != nil {
		return "", "", err
	}

	moduleToolchainMu.Lock()
	defer moduleToolchainMu.Unlock()

	binDir := filepath.Join(live.EmpWorkSpace, moduleToolchainSubdir, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		return "", "", fmt.Errorf("create module toolchain dir: %w", err)
	}

	shim := func(command ...string) string {
		parts := []string{shellQuote(zig)}
		for _, arg := range command {
			parts = append(parts, shellQuote(arg))
		}
		return "#!/bin/sh\nexec " + strings.Join(parts, " ") + " \"$@\"\n"
	}
	linuxCC := shim("cc", "-target", linuxTarget)
	linuxCXX := shim("c++", "-target", linuxTarget)
	win64CC := shim("cc", "-target", "x86_64-windows-gnu")
	win64CXX := shim("c++", "-target", "x86_64-windows-gnu")
	win32CC := shim("cc", "-target", "x86-windows-gnu")
	win32CXX := shim("c++", "-target", "x86-windows-gnu")

	shims := map[string]string{
		"cc": linuxCC, "gcc": linuxCC, "clang": linuxCC,
		"c++": linuxCXX, "g++": linuxCXX, "clang++": linuxCXX,
		"ar": shim("ar"), "ranlib": shim("ranlib"),
		"x86_64-w64-mingw32-gcc": win64CC, "x86_64-w64-mingw32-clang": win64CC,
		"x86_64-w64-mingw32-g++": win64CXX, "x86_64-w64-mingw32-clang++": win64CXX,
		"i686-w64-mingw32-gcc": win32CC, "i686-w64-mingw32-clang": win32CC,
		"i686-w64-mingw32-g++": win32CXX, "i686-w64-mingw32-clang++": win32CXX,
		// The BOF Makefiles call a mingw strip after compiling. The builder
		// image has always provided a no-op shim for it; mirror that here so
		// the operator host needs no mingw binutils.
		"x86_64-w64-mingw32-strip": "#!/bin/sh\nexit 0\n",
		"i686-w64-mingw32-strip":   "#!/bin/sh\nexit 0\n",
	}
	for name, content := range shims {
		path := filepath.Join(binDir, name)
		if existing, readErr := os.ReadFile(path); readErr == nil && string(existing) == content {
			if chmodErr := os.Chmod(path, 0o755); chmodErr != nil {
				return "", "", fmt.Errorf("chmod module shim %s: %w", name, chmodErr)
			}
			continue
		}
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			return "", "", fmt.Errorf("write module shim %s: %w", name, err)
		}
	}
	return binDir, zig, nil
}

// moduleBuildEnv returns the environment for a module build. It puts the zig
// shims first on PATH, adds the shipped zig to PATH for Makefiles that call it
// directly, and exports the conventional compiler variables for Makefiles
// that honour the environment.
func moduleBuildEnv() ([]string, error) {
	binDir, zig, err := ensureModuleToolchain()
	if err != nil {
		return nil, err
	}

	merged := make(map[string]string)
	for _, kv := range os.Environ() {
		key, value, ok := strings.Cut(kv, "=")
		if ok {
			merged[key] = value
		}
	}
	pathEntries := []string{binDir, filepath.Dir(zig)}
	if oldPath := merged["PATH"]; oldPath != "" {
		pathEntries = append(pathEntries, oldPath)
	}
	merged["PATH"] = strings.Join(pathEntries, string(os.PathListSeparator))
	merged["ZIG"] = zig
	merged["CC"] = filepath.Join(binDir, "cc")
	merged["CXX"] = filepath.Join(binDir, "c++")
	merged["AR"] = filepath.Join(binDir, "ar")
	merged["RANLIB"] = filepath.Join(binDir, "ranlib")

	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+merged[key])
	}
	return env, nil
}
