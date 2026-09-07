package transport

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// maxCIDREnumeration caps how many addresses a single IPinCIDR call may
// return. /0-/15 CIDRs would otherwise force the caller to materialize
// millions of strings (memory DoS) even when the result is only used to scan
// a handful of ports.
const maxCIDREnumeration = 65536

// IPinCIDR returns all IPs in a CIDR as "ip:port" strings (port may be ""
// for bare addresses). The address space is capped to avoid unbounded
// allocation on huge CIDRs such as 0.0.0.0/1.
func IPinCIDR(port, cidr string) (ips []string) {
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		logging.Print(err)
		return nil
	}
	// Only IPv4 ranges are supported by the uint32 arithmetic below.
	if subnet.IP.To4() == nil || subnet.Mask == nil {
		logging.Print(fmt.Sprintf("IPinCIDR: unsupported non-IPv4 CIDR %q", cidr))
		return nil
	}
	// convert IPNet struct mask and address to uint32
	// network is BigEndian
	mask := binary.BigEndian.Uint32([]byte(subnet.Mask))
	start := binary.BigEndian.Uint32(subnet.IP.To4())

	// find the final address
	finish := (start & mask) | (mask ^ 0xffffffff)
	if finish < start {
		return nil
	}

	// Guard against overflow of i++ at i == finish == 0xffffffff: use a count
	// bound, which doubles as the anti-DoS cap for huge ranges.
	count := uint64(finish) - uint64(start) + 1
	if count > maxCIDREnumeration {
		logging.Print(fmt.Sprintf("IPinCIDR: range %s has %d addresses, capped at %d", cidr, count, maxCIDREnumeration))
		count = maxCIDREnumeration
	}
	ips = make([]string, 0, count)
	for i := uint64(0); i < count; i++ {
		cur := start + uint32(i)
		// convert back to net.IP
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, cur)
		addr := ip.String()
		if port != "" {
			addr = net.JoinHostPort(addr, port)
		}
		ips = append(ips, addr)
	}

	return ips
}

// ParseTarget parses a target in "ip", "ip:port", "cidr", "cidr:port" or
// "host:port" form and returns a normalized, validated target list. It
// rejects malformed inputs instead of silently passing garbage down to a
// scanner (which previously received raw binary strings from IPinCIDR).
func ParseTarget(target string) ([]string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("empty target")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		// No port given.
		host, port = target, ""
	}
	if strings.Contains(host, "/") {
		// CIDR form.
		if _, _, err := net.ParseCIDR(host); err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %v", host, err)
		}
		ips := IPinCIDR(port, host)
		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses enumerated for %q", host)
		}
		return ips, nil
	}
	if port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("invalid port %q", port)
		}
	}
	return []string{target}, nil
}
