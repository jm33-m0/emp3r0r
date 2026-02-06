//go:build darwin
// +build darwin

package modules

import (
	"fmt"
)

// Copy current executable to a new location
func CopySelfTo(dest_file string) (err error) {
	return fmt.Errorf("Not implemented")
}
