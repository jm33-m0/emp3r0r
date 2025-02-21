package agentutils

import "github.com/jm33-m0/emp3r0r/core/internal/agent/sysinfo"

func CheckContainer() string {
	return sysinfo.CheckContainer()
}
