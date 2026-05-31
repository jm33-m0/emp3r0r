//go:build linux
// +build linux

package netutil

import (
	"fmt"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/vishvananda/netlink"
)

// IPr works like `ip r`, covers both IPv4 and IPv6
func IPr() (routes []string) {
	links := IPLink()
	if links == nil {
		return []string{"N/A"}
	}
	for _, link := range links {
		linkName := linkIdx2Name(link.Attrs().Index)
		if linkName == "lo" {
			continue
		}
		r, err := netlink.RouteList(link, netlink.FAMILY_ALL)
		if err != nil {
			logging.Infof("cannot get route list from %d: %v", link.Attrs().Index, err)
			continue
		}
		for _, route := range r {
			routeStr := route.String()
			if route.Gw != nil {
				routeStr = fmt.Sprintf("default via %s", route.Gw.String())
			}
			if route.Src == nil && route.Dst != nil {
				routeStr = route.Dst.String()
			}
			if route.Src != nil && route.Dst != nil {
				routeStr = fmt.Sprintf("%s via %s", route.Dst.String(), route.Src.String())
			}
			ip := fmt.Sprintf("%s (%s)", routeStr, linkName)
			routes = append(routes, ip)
		}
	}
	return routes
}

// IPLink get all interfaces
func IPLink() (links []netlink.Link) {
	links, err := netlink.LinkList()
	if err != nil {
		logging.Infof("Failed to get network interfaces: %v", err)
		return nil
	}

	return links
}

func linkIdx2Name(index int) (name string) {
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		logging.Infof("Cannot read name from interface %d: %v", index, err)
		return "N/A"
	}

	return link.Attrs().Name
}

// IPNeigh works like `ip neigh`, dumps ARP cache
func IPNeigh() []string {
	var (
		mappings  []string
		neighList []netlink.Neigh
	)
	links := IPLink()
	if links == nil {
		return []string{"N/A"}
	}
	for _, link := range links {
		ifIdx := link.Attrs().Index
		l, err := netlink.NeighList(ifIdx, netlink.FAMILY_ALL)
		neighList = append(neighList, l...)
		if err != nil {
			logging.Infof("Cannot get neigh list on interface %d: %v", ifIdx, err)
			continue
		}
	}

	for _, n := range neighList {
		ipaddr := n.IP.String()
		if ipaddr == "::1" ||
			ipaddr == "127.0.0.1" ||
			strings.HasPrefix(ipaddr, "fe80:") {
			continue
		}
		mappings = append(mappings, fmt.Sprintf("%s (%s)", ipaddr, linkIdx2Name(n.LinkIndex)))
	}

	return mappings
}
