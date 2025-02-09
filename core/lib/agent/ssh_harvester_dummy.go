//go:build !amd64 && linux
// +build !amd64,linux

package agent

import (
	"context"
	"fmt"
	"runtime"
)

var (
	// provide a way to stop the harvester
	SshHarvesterCtx    context.Context
	SshHarvesterCancel context.CancelFunc
)

func sshd_monitor(_ chan string, _ []byte, _ string) (err error) {
	return fmt.Errorf("not supported on %s platform", runtime.GOARCH)
}
