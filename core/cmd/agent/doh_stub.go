//go:build no_doh

package main

import "fmt"

// applyDoHResolver is the stub used when the build excludes DoH support.
func applyDoHResolver(server string) error {
	if server == "" {
		return nil
	}
	return fmt.Errorf("DoH resolver support is not compiled into this agent")
}
