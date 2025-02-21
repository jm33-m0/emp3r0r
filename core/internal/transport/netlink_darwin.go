//go:build darwin
// +build darwin

package transport

import (
	"github.com/vishvananda/netlink"
)

// IPr works like `ip r`, covers both IPv4 and IPv6
func crossPlatformIPr() (routes []string) {
	return
}

// IPLink get all interfaces
func IPLink() (links []netlink.Link) {
	return
}

func linkIdx2Name(index int) (name string) {
	return
}

// IPNeigh works like `ip neigh`, dumps ARP cache
func crossPlatformIPNeigh() []string {
	return []string{"N/A"}
}
