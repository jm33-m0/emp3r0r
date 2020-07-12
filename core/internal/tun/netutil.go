package tun

import (
	"net"
	"strconv"
	"strings"
	"time"
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
	if err != nil {
		return false
	}
	return true
}

// IsTor2Web check if CC address is a tor2web service
func IsTor2Web(addr string) bool {
	fields := strings.Split(addr, ":")
	return fields[len(fields)-2] == "onion"
}
