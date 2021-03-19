package tun

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
)

// IsPortOpen is this TCP port open?
func IsPortOpen(host string, port string) bool {
	timeout := time.Second
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

// HasInternetAccess does this machine has internet access, if yes, what's its exposed IP?
func HasInternetAccess() bool {
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("http://www.msftncsi.com/ncsi.txt")
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	if string(respData) == "Microsoft NCSI" {
		return true
	}
	return false
}

// IsProxyOK test if the proxy works
func IsProxyOK(proxy string) bool {
	tr := &http.Transport{}
	proxyUrl, err := url.Parse(proxy)
	if err != nil {
		log.Printf("Invalid proxy: %v", err)
		return false
	}
	tr.Proxy = http.ProxyURL(proxyUrl)
	client := http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	resp, err := client.Get("http://www.msftncsi.com/ncsi.txt")
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	if string(respData) == "Microsoft NCSI" {
		return true
	}
	return false
}

// CollectLocalIPs works like `ip a`
func CollectLocalIPs() (ips []string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return []string{"Not available"}
	}

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ipaddr := ip.String()
			if ipaddr == "::1" ||
				ipaddr == "127.0.0.1" ||
				strings.HasPrefix(ipaddr, "fe80:") {
				continue
			}

			ips = append(ips, ipaddr)
		}
	}

	return
}

// IPa works like `ip addr`, covers both IPv4 and IPv6
func IPa() (ips []string) {
	links := IPLink()
	if links == nil {
		return []string{"N/A"}
	}
	for _, link := range links {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			log.Printf("cannot get addr list from %d: %v", link.Attrs().Index, err)
			continue
		}
		for _, addr := range addrs {
			ip := fmt.Sprintf("%s (%s)", addr.IP.String(), linkIdx2Name(link.Attrs().Index))
			ips = append(ips, ip)
		}
	}

	return
}

// IPaddr returns netlink.Addr in IPv4
func IPaddr() (ips []netlink.Addr) {
	links := IPLink()
	if links == nil {
		return nil
	}
	for _, link := range links {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			log.Printf("cannot get addr list from %d: %v", link.Attrs().Index, err)
			continue
		}
		for _, addr := range addrs {
			ips = append(ips, addr)
		}
	}
	return
}

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
			log.Printf("cannot get route list from %d: %v", link.Attrs().Index, err)
			continue
		}
		for _, route := range r {
			routeStr := route.String()
			if route.Gw != nil {
				routeStr = fmt.Sprintf("default via %s", route.Gw.String())
			}
			if route.Src == nil && route.Dst != nil {
				routeStr = fmt.Sprintf("%s", route.Dst.String())
			}
			if route.Src != nil && route.Dst != nil {
				routeStr = fmt.Sprintf("%s via %s", route.Dst.String(), route.Src.String())
			}
			ip := fmt.Sprintf("%s (%s)", routeStr, linkName)
			routes = append(routes, ip)
		}
	}
	return
}

// IPLink get all interfaces
func IPLink() (links []netlink.Link) {
	links, err := netlink.LinkList()
	if err != nil {
		log.Printf("Failed to get network interfaces: %v", err)
		return nil
	}

	return
}

func linkIdx2Name(index int) (name string) {
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		log.Printf("Cannot read name from interface %d: %v", index, err)
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
			log.Printf("Cannot get neigh list on interface %d: %v", ifIdx, err)
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
