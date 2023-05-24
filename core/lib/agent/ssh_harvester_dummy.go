//go:build !amd64 && linux
// +build !amd64,linux

package agent

import (
	"fmt"
	"runtime"
)

func sshd_monitor(password_file string) (err error) {
	return fmt.Errorf("Not supported on %s platform", runtime.GOARCH)
}
