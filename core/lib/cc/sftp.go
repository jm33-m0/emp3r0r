//go:build linux
// +build linux

package cc

import "github.com/spf13/cobra"

func OpenFileManager(cmd *cobra.Command, args []string) {
	sshErr := SSHClient("sftp", "", RuntimeConfig.SSHDShellPort, false)
	if sshErr != nil {
		CliPrintError("openFileManager: %v", sshErr)
	}
}
