package cc

func OpenFileManager() {
	err := SSHClient("sftp", "", RuntimeConfig.SSHDPort, false)
	if err != nil {
		CliPrintError("OpenFileManager: %v", err)
	}
	return
}
