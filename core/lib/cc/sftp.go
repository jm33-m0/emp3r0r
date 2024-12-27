//go:build linux
// +build linux

package cc

func OpenFileManager() {
	sshErr := SSHClient("sftp", "", RuntimeConfig.SSHDShellPort, false)
	if sshErr != nil {
		CliPrintError("openFileManager: %v", sshErr)
	}
}
