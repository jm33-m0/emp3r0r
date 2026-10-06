//go:build !no_cdnproxy

package main

import (
	cdn2proxy "github.com/jm33-m0/go-cdn2proxy"
)

// runCDNProxy starts the agent-side CDN fronting proxy. It is only linked into
// builds that keep this file; minimal agents drop the dependency entirely.
func runCDNProxy(localAddr, cdnProxy, upperProxy, dohURL string) error {
	return cdn2proxy.StartProxy(localAddr, cdnProxy, upperProxy, dohURL)
}
