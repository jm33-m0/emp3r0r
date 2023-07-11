//go:build !linux
// +build !linux

package agent

import (
	"fmt"
	"runtime"
)

func VaccineHandler() string {
	return fmt.Sprintf("Not supported on %s platform", runtime.GOARCH)
}
