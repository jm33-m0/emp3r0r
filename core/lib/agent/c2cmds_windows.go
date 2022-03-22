//go:build windows
// +build windows

package agent

import (
	"fmt"
)

func platformC2CommandsHandler(cmdSlice []string) (out string) {
	switch cmdSlice[0] {
	}

	return fmt.Sprintf("Unknown command %v", cmdSlice)
}
