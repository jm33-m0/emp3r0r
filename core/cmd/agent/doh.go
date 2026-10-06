//go:build !no_doh

package main

import (
	"net"

	"github.com/ncruces/go-dns"
)

// applyDoHResolver installs a DNS-over-HTTPS resolver when server is set.
// The DoH dependency (ncruces/go-dns, miekg/dns) is only linked into builds
// that keep this file; minimal agents answer DNS through the OS resolver.
func applyDoHResolver(server string) error {
	if server == "" {
		return nil
	}
	resolver, err := dns.NewDoHResolver(server, dns.DoHCache())
	if err != nil {
		return err
	}
	net.DefaultResolver = resolver
	return nil
}
