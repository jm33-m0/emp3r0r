package agent

func SSHD(shell, port string, args []string) (err error) {
	return crossPlatformSSHD(shell, port, args)
}
