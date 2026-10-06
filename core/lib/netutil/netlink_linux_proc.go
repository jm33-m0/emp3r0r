//go:build linux && no_netlink

// Pure-procfs fallback for builds that exclude vishvananda/netlink. The agent
// only needs route/neighbour tables to render shellhelper's `ip` output, and
// /proc/net/{route,arp} always exist on Linux, so dropping the netlink module
// costs no functionality.
package netutil

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// IPr works like `ip r` for IPv4 routes, reading the kernel's procfs table.
func IPr() (routes []string) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return []string{"N/A"}
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Skip the header line.
	if !scanner.Scan() {
		return []string{"N/A"}
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		iface := fields[0]
		if iface == "lo" {
			continue
		}
		dst := procHexIPv4(fields[1])
		gw := procHexIPv4(fields[2])
		mask := procHexIPv4(fields[7])
		if dst == "" {
			continue
		}
		switch {
		case dst == "0.0.0.0" && gw != "":
			routes = append(routes, fmt.Sprintf("default via %s (%s)", gw, iface))
		case gw != "":
			routes = append(routes, fmt.Sprintf("%s/%d via %s (%s)", dst, procMaskLen(mask), gw, iface))
		default:
			routes = append(routes, fmt.Sprintf("%s/%d (%s)", dst, procMaskLen(mask), iface))
		}
	}
	if len(routes) == 0 {
		return []string{"N/A"}
	}
	return routes
}

// IPNeigh works like `ip neigh`, reading the kernel's ARP cache.
func IPNeigh() []string {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return []string{"N/A"}
	}
	defer f.Close()

	var mappings []string
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return []string{"N/A"}
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		ip := fields[0]
		mac := fields[3]
		if mac == "00:00:00:00:00:00" {
			continue
		}
		mappings = append(mappings, fmt.Sprintf("%s (%s)", ip, mac))
	}
	if len(mappings) == 0 {
		return []string{"N/A"}
	}
	return mappings
}

// procHexIPv4 decodes the little-endian hex representation used by
// /proc/net/route into dotted-quad form.
func procHexIPv4(s string) string {
	v, err := parseProcHex(s)
	if err != nil {
		return ""
	}
	ip := net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	return ip.String()
}

func parseProcHex(s string) (uint32, error) {
	var v uint32
	if _, err := fmt.Sscanf(s, "%x", &v); err != nil {
		return 0, err
	}
	return v, nil
}

// procMaskLen converts a dotted-quad mask to its prefix length.
func procMaskLen(mask string) int {
	ip := net.ParseIP(mask)
	if ip == nil {
		return 0
	}
	ones, _ := net.IPMask(ip.To4()).Size()
	return ones
}
