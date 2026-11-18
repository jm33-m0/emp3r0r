package modules

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// CrystalPackAvailable reports whether the crystal_pack producer can link a
// PICO on this host. It mirrors build.sh: the vendored Crystal Palace
// distribution, the loader spec, a Java runtime, a Windows C compiler, and
// nasm must all be resolvable.
func CrystalPackAvailable(dir string) bool {
	dir = strings.TrimSpace(dir)
	for _, required := range []string{
		filepath.Join(dir, "crystalpalace", "crystalpalace.jar"),
		filepath.Join(dir, "postex-loader", "loader.spec"),
		filepath.Join(dir, "libtcg.x64.zip"),
	} {
		if info, err := os.Stat(required); err != nil || !info.Mode().IsRegular() {
			return false
		}
	}
	return crystalPackToolchain() && findJava() != ""
}

// crystalPackToolchain mirrors build.sh: postex-loader objects are rebuilt on
// every link, so a Windows C compiler and nasm must be resolvable. CC_64 and
// ZIG may contain arguments (for example "zig cc -target ..."), so only the
// command word is resolved.
func crystalPackToolchain() bool {
	compiler := strings.TrimSpace(os.Getenv("CC_64"))
	if compiler == "" {
		if commandExists("x86_64-w64-mingw32-gcc") {
			compiler = "x86_64-w64-mingw32-gcc"
		} else {
			compiler = strings.TrimSpace(os.Getenv("ZIG"))
			if compiler == "" {
				compiler = "zig"
			}
		}
	}
	if !commandExists(compiler) {
		return false
	}
	nasm := strings.TrimSpace(os.Getenv("NASM"))
	if nasm == "" {
		nasm = "nasm"
	}
	return commandExists(nasm)
}

// findJava resolves a Java runtime the same way build.sh does: explicit JAVA,
// JAVA_HOME, PATH, the shipped operator tree, and the common package paths.
// It returns an empty string when none is executable.
func findJava() string {
	if command := strings.TrimSpace(os.Getenv("JAVA")); command != "" {
		if commandExists(command) {
			return command
		}
		return ""
	}
	if home := strings.TrimSpace(os.Getenv("JAVA_HOME")); home != "" {
		candidate := filepath.Join(home, "bin", "java")
		if isExecutable(candidate) {
			return candidate
		}
	}
	if path, err := exec.LookPath("java"); err == nil {
		return path
	}
	candidates := []string{
		filepath.Join(live.EmpDataDir, "jre", "bin", "java"),
		filepath.Join(live.EmpWorkSpace, "jre", "bin", "java"),
	}
	if matches, err := filepath.Glob("/usr/lib/jvm/*/bin/java"); err == nil {
		candidates = append(candidates, matches...)
	}
	for _, candidate := range candidates {
		if isExecutable(candidate) {
			return candidate
		}
	}
	return ""
}

// commandExists reports whether the first word of a shell command is an
// executable. Environment overrides such as CC_64 can carry target flags.
func commandExists(command string) bool {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return false
	}
	_, err := exec.LookPath(fields[0])
	return err == nil
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0
}
