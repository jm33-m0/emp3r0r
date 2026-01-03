//go:build !linux
// +build !linux

package modules

import (
	"runtime"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func VaccineHandler(_, _ string) string {
	return logging.Sprintf("Not supported on %s platform", runtime.GOARCH)
}
