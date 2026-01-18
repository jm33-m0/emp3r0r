//go:build linux && !cgo
// +build linux,!cgo

package coffloader

import "fmt"

func RunLinuxCOFF(_ []byte, _ string, _ []CoffArg) (string, error) {
	return "", fmt.Errorf("linux BOF loader requires cgo")
}
