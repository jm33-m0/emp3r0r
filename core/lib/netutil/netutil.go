package netutil

import (
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// JoinURL joins base URL and path segments, ensuring correct slash usage.
func JoinURL(base string, paths ...string) string {
	res, err := url.JoinPath(base, paths...)
	if err != nil {
		logging.Errorf("JoinURL: %v", err)
		return base + "/" + strings.Join(paths, "/")
	}
	return strings.TrimSuffix(res, "/")
}

const (
	// MicrosoftNCSIURL is the URL used by Microsoft to check internet connectivity
	MicrosoftNCSIURL  = "http://www.msftncsi.com/ncsi.txt"
	MicrosoftNCSIResp = "Microsoft NCSI"

	// UbuntuConnectivityURL is the URL used by Ubuntu to check internet connectivity
	UbuntuConnectivityURL = "https://connectivity-check.ubuntu.com"
	// UbuntuConnectivityResp will be empty with 204 status code
	UbuntuConnectivityResp = 204
)

// IsPortOpen is this TCP port open?
func IsPortOpen(host string, port string) bool {
	timeout := 3 * time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return false
	}
	if conn != nil {
		defer conn.Close()
		return true
	}
	return false
}

// ValidateIP is this IP legit?
func ValidateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// ValidateHostName is this domain legit?
func ValidateHostName(name string) bool {
	// if it's an IP
	if ValidateIP(name) {
		return true
	}

	return ValidateDomain(name) || IsValidWindowsComputerName(name)
}

func IsValidWindowsComputerName(name string) bool {
	validNamePattern := `^[a-zA-Z0-9\-]{1,15}$`
	matched, _ := regexp.MatchString(validNamePattern, name)
	return matched
}

func ValidateDomain(domain string) bool {
	// regex to match domain name
	re := regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)
	return re.MatchString(domain)
}

// ValidateIPPort check if the host string looks like IP:Port
func ValidateIPPort(to string) bool {
	fields := strings.Split(to, ":")
	if len(fields) != 2 {
		return false
	}
	host := fields[0]
	if !ValidateIP(host) {
		return false
	}
	_, err := strconv.Atoi(fields[1])
	return err == nil
}

// IsTor is the C2 on Tor?
func IsTor(addr string) bool {
	if !strings.HasPrefix(addr, "http://") &&
		!strings.HasPrefix(addr, "https://") {
		return false
	}
	nopath := strings.Split(addr, "/")[2]
	fields := strings.Split(nopath, ".")
	return fields[len(fields)-1] == "onion"
}

// IPWithMask net.IP and net.IPMask
type IPWithMask struct {
	IP   net.IP
	Mask net.IPMask
}

// IPa works like `ip addr`, you get a list of IP strings
func IPa() (ips []string) {
	netips := IPaddr()
	if netips == nil {
		return []string{"Unknown"}
	}

	for _, netip := range netips {
		maskLen, _ := netip.Mask.Size()
		ip := netip.IP.String() + "/" + strconv.Itoa(maskLen)
		ips = append(ips, ip)
	}

	return
}

// IPaddr returns a list of local IP addresses
func IPaddr() (ips []IPWithMask) {
	ifaces := IPIfaces()
	if ifaces == nil {
		return nil
	}

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			var mask net.IPMask
			var ipMask IPWithMask
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				mask = v.Mask
			case *net.IPAddr:
				ip = v.IP
				mask = ip.DefaultMask()
			}
			ipaddr := ip.String()
			if ipaddr == "::1" ||
				ipaddr == "127.0.0.1" ||
				strings.HasPrefix(ipaddr, "fe80:") ||
				strings.HasPrefix(ipaddr, "169.254") {
				continue
			}
			ipMask.IP = ip
			ipMask.Mask = mask

			ips = append(ips, ipMask)
		}

	}
	return
}

// IPIfaces returns a list of network interfaces
func IPIfaces() (ifaces []net.Interface) {
	ifaces, err := net.Interfaces()
	if err != nil {
		logging.Printf("IPIfaces: %v", err)
		return nil
	}
	return
}

// IPbroadcastAddr calculate broadcast address of an IP
func IPbroadcastAddr(ipMask IPWithMask) string {
	ip := ipMask.IP
	mask := ipMask.Mask

	// check if IP is a valid IPv4 address
	if ip.To4() == nil {
		logging.Printf("%s is not a valid IPv4 address", ip.String())
		return ""
	}

	broadcast := net.IP(make([]byte, 4))
	for i, p := range ip.To4() {
		broadcast[i] = p | ^mask[i]
	}
	return broadcast.String()
}

// FindIPToUse find an IP that resides in target IP range
// target: 192.168.1.1/24
func FindIPToUse(target string) string {
	_, subnet, _ := net.ParseCIDR(target)
	for _, ipnetstr := range IPa() {
		ipstr := strings.Split(ipnetstr, "/")[0]
		ip := net.ParseIP(ipstr)
		if ip == nil {
			continue
		}
		if subnet.Contains(ip) {
			return ip.String()
		}
	}
	return ""
}

// GenerateRandomSubnet24 generates a random /24 subnet
func GenerateRandomSubnet24() string {
	first := rand.Intn(256)
	second := rand.Intn(256)
	third := rand.Intn(256)

	return fmt.Sprintf("%d.%d.%d.0/24", first, second, third)
}

// GenerateRandomPrivateSubnet24 generates a random private /24 subnet from RFC 1918 address space
func GenerateRandomPrivateSubnet24() string {
	// Choose which private address range to use

	rangeType := rand.Intn(3)

	var first, second, third int

	switch rangeType {
	case 0:
		// 10.0.0.0/8 range
		first = 10
		second = rand.Intn(256)
		third = rand.Intn(256)
	case 1:
		// 172.16.0.0/12 range
		first = 172
		second = rand.Intn(16) + 16 // 16-31
		third = rand.Intn(256)
	case 2:
		// 192.168.0.0/16 range
		first = 192
		second = 168
		third = rand.Intn(256)
	}

	return fmt.Sprintf("%d.%d.%d.0/24", first, second, third)
}

// GenerateRandomIPInSubnet24 generates a random IP within the given /24 subnet
func GenerateRandomIPInSubnet24(subnet string) (string, error) {
	// Parse the subnet
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("invalid subnet: %v", err)
	}

	// Get the first three octets from the subnet IP
	ip := ipNet.IP.To4()
	if ip == nil {
		return "", fmt.Errorf("not an IPv4 address")
	}

	// Generate random last octet (1-254, avoiding 0 and 255)
	lastOctet := rand.Intn(254) + 1

	// Create a new IP
	randomIP := net.IPv4(ip[0], ip[1], ip[2], byte(lastOctet))

	return randomIP.String(), nil
}
