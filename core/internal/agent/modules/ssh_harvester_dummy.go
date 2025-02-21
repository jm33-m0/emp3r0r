//go:build !amd64 && linux
// +build !amd64,linux

package modules

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"github.com/spf13/cobra"
)

var (
	// harvester logging, to send back to C2
	harvesterLogStream chan string

	// mark ssh harvester as running
	SshHarvesterRunning bool

	// record traced sshd sessions
	traced_pids     = make(map[int]bool)
	traced_pids_mut = &sync.RWMutex{}

	// provide a way to stop the harvester
	SshHarvesterCtx    context.Context
	SshHarvesterCancel context.CancelFunc
)

func SshHarvester(_ *cobra.Command, _ []byte, _ string) (err error) {
	return fmt.Errorf("not supported on %s platform", runtime.GOARCH)
}
