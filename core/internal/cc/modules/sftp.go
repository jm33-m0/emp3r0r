package modules

import (
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/spf13/cobra"
)

// CmdOpenFileManager open SFTP file manager on target machine
func CmdOpenFileManager(cmd *cobra.Command, args []string) {
	sshErr := SSHClient("sftp", "", live.RuntimeConfig.SSHDShellPort, false)
	if sshErr != nil {
		logging.Errorf("openFileManager: %v", sshErr)
	}
}
