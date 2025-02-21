//go:build !linux
// +build !linux

package modules

import (
	"fmt"
	"runtime"
)

func VaccineHandler(_, _ string) string {
	return fmt.Sprintf("Not supported on %s platform", runtime.GOARCH)
}
