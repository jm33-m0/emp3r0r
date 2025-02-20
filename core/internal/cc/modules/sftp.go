package modules

import (
	"github.com/jm33-m0/emp3r0r/core/internal/logging"
	"github.com/jm33-m0/emp3r0r/core/internal/runtime_def"
	"github.com/spf13/cobra"
)

// CmdOpenFileManager open SFTP file manager on target machine
func CmdOpenFileManager(cmd *cobra.Command, args []string) {
	sshErr := SSHClient("sftp", "", runtime_def.RuntimeConfig.SSHDShellPort, false)
	if sshErr != nil {
		logging.Errorf("openFileManager: %v", sshErr)
	}
}
