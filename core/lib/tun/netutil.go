package tun

import (
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	MicrosoftNCSIURL  = "http://www.msftncsi.com/ncsi.txt"
	MicrosoftNCSIResp = "Microsoft NCSI"
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

// HasInternetAccess does this machine has internet access,
// does NOT use any proxies
func HasInternetAccess(test_url string) bool {
	// use Microsoft NCSI as default
	// NCSI is an HTTP service therefore we don't need
	// uTLS to talk to it
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	// if not using Microsoft NCSI, we need to use uTLS
	if test_url != MicrosoftNCSIURL {
		client = HTTPClientWithEmpCA(test_url, "")
		if client == nil {
			log.Printf("HasInternetAccess: cannot create http client for %s", test_url)
			return false
		}
	}

	resp, err := client.Get(test_url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	if test_url == MicrosoftNCSIURL {
		return string(respData) == MicrosoftNCSIResp
	}
	return true
}

// IsProxyOK test if the proxy works against the test URL
func IsProxyOK(proxy, test_url string) bool {
	client := HTTPClientWithEmpCA(test_url, proxy)
	if client == nil {
		log.Printf("IsProxyOK: cannot create http client")
		return false
	}
	resp, err := client.Get(test_url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	log.Printf("IsProxyOK: testing proxy %s: %s", proxy, respData)
	if test_url == MicrosoftNCSIURL {
		return string(respData) == MicrosoftNCSIResp
	}
	return true
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
		log.Printf("IPIfaces: %v", err)
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
		log.Printf("%s is not a valid IPv4 address", ip.String())
		return ""
	}

	broadcast := net.IP(make([]byte, 4))
	for i, p := range ip.To4() {
		broadcast[i] = p | ^mask[i]
	}
	return broadcast.String()
}

// IPr works like `ip r`, covers both IPv4 and IPv6
func IPr() (routes []string) {
	return crossPlatformIPr()
}

// IPNeigh works like `ip neigh`, dumps ARP cache
func IPNeigh() []string {
	return crossPlatformIPNeigh()
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
