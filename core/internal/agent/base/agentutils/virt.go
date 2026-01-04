package agentutils

import "github.com/jm33-m0/emp3r0r/core/lib/sysinfo"

func checkContainer() string {
	return sysinfo.CheckContainer()
}
