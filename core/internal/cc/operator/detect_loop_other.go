//go:build !linux

package operator

import "os/exec"

func detachWorker(*exec.Cmd) {}
