//go:build !amd64 && linux
// +build !amd64,linux

package agent

import (
	"fmt"
	"runtime"
)

func sshd_monitor(_ string) (err error) {
	return fmt.Errorf("not supported on %s platform", runtime.GOARCH)
}
