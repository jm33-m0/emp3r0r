//go:build !linux || !amd64

package modules

import (
	"context"
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	// mark ssh harvester as running
	SshHarvesterRunning bool

	// provide a way to stop the harvester
	SshHarvesterCtx    context.Context
	SshHarvesterCancel context.CancelFunc
)

func SshHarvester(_ *cobra.Command, _ []byte, _ string) (err error) {
	return fmt.Errorf("not supported on %s platform", runtime.GOARCH)
}
