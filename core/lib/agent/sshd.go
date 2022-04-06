package agent

import (
	"fmt"
	"strings"
)

func SSHD(shell, port string, args []string) (err error) {
	if shell == "" {
		return fmt.Errorf("Please specify a shell to use")
	}
	if strings.TrimSpace(strings.Join(args, " ")) == "--" {
		args = []string{""}
	}
	return crossPlatformSSHD(shell, port, args)
}
