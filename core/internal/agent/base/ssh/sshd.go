package ssh

import (
	"fmt"
	"strings"
)

func SSHD(shell, port string, args []string) (err error) {
	if shell == "" {
		return fmt.Errorf("please specify a shell to use")
	}
	if strings.TrimSpace(strings.Join(args, " ")) == "--" {
		args = []string{""}
	}

	// No need to prepend AgentRoot anymore, it's deprecated

	return crossPlatformSSHD(shell, port, args)
}
