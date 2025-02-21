//go:build darwin
// +build darwin

package agent

import "fmt"

// Screenshot take a screenshot
// returns path of taken screenshot
func Screenshot() (path string, err error) {
	return "", fmt.Errorf("not supported")
}
