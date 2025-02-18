package core

import (
	"github.com/jm33-m0/emp3r0r/core/lib/cc/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/spf13/cobra"
)

func OpenFileManager(cmd *cobra.Command, args []string) {
	sshErr := SSHClient("sftp", "", def.RuntimeConfig.SSHDShellPort, false)
	if sshErr != nil {
		logging.Errorf("openFileManager: %v", sshErr)
	}
}
