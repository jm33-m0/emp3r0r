//go:build no_cdnproxy

package main

import "fmt"

// runCDNProxy is the stub used when the build excludes CDN fronting support.
func runCDNProxy(localAddr, cdnProxy, upperProxy, dohURL string) error {
	return fmt.Errorf("CDN proxy support is not compiled into this agent")
}
