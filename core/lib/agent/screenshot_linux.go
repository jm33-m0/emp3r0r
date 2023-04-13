//go:build linux
// +build linux

package agent

import "fmt"

// Screenshot take a screenshot
// returns path of taken screenshot
func Screenshot() (path string, err error) {
	return "", fmt.Errorf("Not supported")
}
