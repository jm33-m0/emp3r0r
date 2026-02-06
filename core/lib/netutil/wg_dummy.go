//go:build !linux
// +build !linux

package netutil

import (
	"context"
	"errors"
)

// LogLevel specifies the verbosity of logging
type LogLevel int

// Log level constants
const (
	LogLevelSilent  LogLevel = 0
	LogLevelError   LogLevel = 1
	LogLevelVerbose LogLevel = 2

	// WgFileServerPort port for file server
	WgFileServerPort = 7000
)

var (
	WgSubnet     = "172.16.254.0/24" // WireGuard subnet
	WgServerIP   = "172.16.254.1"    // server's static WireGuard IP
	WgOperatorIP = "172.16.254.2"    // operator's static WireGuard IP

	// WgRelayedHTTPPort port for relayed HTTP server
	WgRelayedHTTPPort = 1025
	WgServer          *WireGuardDevice // server's WireGuard device
	WgOperator        *WireGuardDevice // operator's WireGuard device
)

type WireGuardConfig struct {
	// Interface name (e.g. "wg0")
	InterfaceName string
	// IP address with CIDR (e.g. "192.168.2.1/24")
	IPAddress string
	// Private key (optional, will be generated if empty)
	PrivateKey string
	// UDP listen port for WireGuard
	ListenPort int
	// Log verbosity level
	LogLevel LogLevel
	// Peer configurations
	Peers []PeerConfig
}

// WireGuardDevice represents a WireGuard virtual network interface
type WireGuardDevice struct {
	// Interface name (e.g. "wg0")
	Name string
	// IP address with CIDR (e.g. "192.168.2.1/24")
	IPAddress string
	// WireGuard private key
	PrivateKey string
	// Generated public key (derived from private key)
	PublicKey string
	// UDP listen port for WireGuard
	ListenPort int
	// Log verbosity level
	LogLevel LogLevel
	// Context of the WireGuard device
	Context context.Context
	// Cancel function for the context
	Cancel context.CancelFunc

	// Underlying device objects
	// device   *device.Device
	// tun      tun.Device
	// uapi     net.Listener
	// uapiFile *os.File
	// logger   *device.Logger
}

// PeerConfig represents WireGuard peer configuration
type PeerConfig struct {
	// Public key of the peer
	PublicKey string
	// Comma-separated list of allowed IPs (e.g. "10.0.0.0/24,192.168.1.0/24")
	AllowedIPs string
	// Endpoint address of the peer (e.g. "example.com:51820")
	Endpoint string
}

// Dummy implementations that return errors since WireGuard is not supported on non-Linux platforms

// GeneratePrivateKey creates a new random WireGuard private key
func GeneratePrivateKey() (string, error) {
	return "", errors.New("WireGuard is not supported on this platform")
}

// PublicKeyFromPrivate derives the public key from a private key
func PublicKeyFromPrivate(privateKey string) (string, error) {
	return "", errors.New("WireGuard is not supported on this platform")
}

// Close shuts down the WireGuard device
func (w *WireGuardDevice) Close() {
	// No-op for dummy implementation
}

// WaitShutdown waits for the device to be shut down
func (w *WireGuardDevice) WaitShutdown() {
	// No-op for dummy implementation
}

// ConfigureWireGuardDevice configures the WireGuard device with the given peers
func (w *WireGuardDevice) ConfigureWireGuardDevice(peers []PeerConfig) error {
	return errors.New("WireGuard is not supported on this platform")
}

// CreateWireGuardDevice creates and configures a new WireGuard interface
func CreateWireGuardDevice(config WireGuardConfig) (*WireGuardDevice, error) {
	return nil, errors.New("WireGuard is not supported on this platform")
}

// WireGuardDeviceInfo returns information about the WireGuard device
func (w *WireGuardDevice) WireGuardDeviceInfo() string {
	return "WireGuard is not supported on this platform"
}

// WireGuardMain provides the main entry point for using this library programmatically
func WireGuardMain(config WireGuardConfig) (wg *WireGuardDevice, err error) {
	return nil, errors.New("WireGuard is not supported on this platform")
}
