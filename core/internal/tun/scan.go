package tun

import (
	"encoding/binary"
	"log"
	"net"
)

// IPinCIDR all IPs in a CIDR
func IPinCIDR(port, cidr string) (ips []string) {
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Print(err)
		return nil
	}
	// convert IPNet struct mask and address to uint32
	// network is BigEndian
	mask := binary.BigEndian.Uint32(subnet.Mask)
	start := binary.BigEndian.Uint32(subnet.IP)

	// find the final address
	finish := (start & mask) | (mask ^ 0xffffffff)

	// loop through addresses as uint32
	for i := start; i <= finish; i++ {
		// convert back to net.IP
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		ips = append(ips, string(ip))
	}

	return
}
