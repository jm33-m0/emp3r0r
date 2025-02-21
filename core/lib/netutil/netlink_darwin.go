//go:build darwin
// +build darwin

package netutil

import (
	"github.com/vishvananda/netlink"
)

// IPr works like `ip r`, covers both IPv4 and IPv6
func IPr() (routes []string) {
	return
}

// IPLink get all interfaces
func IPLink() (links []netlink.Link) {
	return
}

// IPNeigh works like `ip neigh`, dumps ARP cache
func IPNeigh() []string {
	return []string{"N/A"}
}
