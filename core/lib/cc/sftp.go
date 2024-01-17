package cc

func OpenFileManager() {
	err := SSHClient("sftp", "", RuntimeConfig.SSHDShellPort, false)
	if err != nil {
		CliPrintError("OpenFileManager: %v", err)
	}
	return
}
