//go:build linux
// +build linux

package netutil

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LogLevel specifies the verbosity of logging
type LogLevel int

// Log level constants
const (
	LogLevelSilent  LogLevel = device.LogLevelSilent
	LogLevelError   LogLevel = device.LogLevelError
	LogLevelVerbose LogLevel = device.LogLevelVerbose

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
	device   *device.Device
	tun      tun.Device
	uapi     net.Listener
	uapiFile *os.File
	logger   *device.Logger
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

// WireGuardConfig contains all configuration parameters for a WireGuard interface
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

// GeneratePrivateKey creates a new random WireGuard private key
func GeneratePrivateKey() (string, error) {
	key := make([]byte, wgtypes.KeyLen)
	_, err := rand.Read(key)
	if err != nil {
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// PublicKeyFromPrivate derives the public key from a private key
func PublicKeyFromPrivate(privateKey string) (string, error) {
	privKeyBytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("invalid base64 in private key: %w", err)
	}

	var privKey wgtypes.Key
	copy(privKey[:], privKeyBytes)
	pubKey := privKey.PublicKey()

	return pubKey.String(), nil
}

// Close shuts down the WireGuard device and releases resources
func (w *WireGuardDevice) Close() {
	if w.uapi != nil {
		w.uapi.Close()
		w.uapi = nil
	}

	if w.device != nil {
		w.device.Close()
		w.device = nil
	}

	if w.uapiFile != nil {
		w.uapiFile.Close()
		w.uapiFile = nil
	}
	if w.Cancel != nil {
		w.Cancel()
	}
}

// WaitShutdown blocks until the device is shut down or a termination signal is received
func (w *WireGuardDevice) WaitShutdown() {
	if w.device == nil {
		return
	}

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	signal.Notify(term, unix.SIGTERM)
	signal.Notify(term, os.Interrupt)

	// Wait for termination
	select {
	case <-term:
		w.logger.Verbosef("Received termination signal")
	case <-errs:
		w.logger.Errorf("Error occurred")
	case <-w.device.Wait():
		w.logger.Verbosef("Device closed")
	case <-w.Context.Done():
		w.logger.Verbosef("Context done")
	}

	// Clean up
	w.Close()
}

// ConfigureWireGuardDevice configures the WireGuard device with the specified private key, listen port and peers
func (w *WireGuardDevice) ConfigureWireGuardDevice(peers []PeerConfig) error {
	// Configure the interface
	return configureInterface(w.Name, w.PrivateKey, w.ListenPort, peers)
}

// CreateWireGuardDevice creates and configures a new WireGuard interface
func CreateWireGuardDevice(config WireGuardConfig) (*WireGuardDevice, error) {
	var err error
	wg := &WireGuardDevice{
		Name:       config.InterfaceName,
		IPAddress:  config.IPAddress,
		PrivateKey: config.PrivateKey,
		ListenPort: config.ListenPort,
		LogLevel:   config.LogLevel,
	}

	// Create context
	wg.Context, wg.Cancel = context.WithCancel(context.Background())

	// Validate IP address format
	_, _, err = net.ParseCIDR(config.IPAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address format: %w", err)
	}

	// Create logger
	wg.logger = device.NewLogger(
		int(config.LogLevel),

		fmt.Sprintf("(%s) ", config.InterfaceName),
	)

	// Generate private key if not provided
	if wg.PrivateKey == "" {
		wg.PrivateKey, err = GeneratePrivateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
		wg.logger.Verbosef("Generated private key")
	}

	// Get public key
	wg.PublicKey, err = PublicKeyFromPrivate(wg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	// Create TUN device
	wg.logger.Verbosef("Creating interface %s...", wg.Name)
	wg.tun, err = tun.CreateTUN(wg.Name, device.DefaultMTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	// Get actual interface name (might be different from requested)
	realInterfaceName, err := wg.tun.Name()
	if err == nil {
		wg.Name = realInterfaceName
	}

	// Create WireGuard device
	wg.device = device.NewDevice(wg.tun, conn.NewDefaultBind(), wg.logger)
	wg.logger.Verbosef("WireGuard device started")

	// Open UAPI file for configuration
	wg.logger.Verbosef("Starting UAPI listener...")
	wg.uapiFile, err = ipc.UAPIOpen(wg.Name)
	if err != nil {
		wg.Close()
		return nil, fmt.Errorf("UAPI listen error: %w", err)
	}

	// Set up UAPI listener
	wg.uapi, err = ipc.UAPIListen(wg.Name, wg.uapiFile)
	if err != nil {
		wg.Close()
		return nil, fmt.Errorf("failed to listen on UAPI socket: %w", err)
	}

	// Start handling UAPI connections
	go func() {
		for {
			conn, err := wg.uapi.Accept()
			if err != nil {
				wg.logger.Errorf("Error accepting UAPI connection: %v", err)
				return
			}
			go wg.device.IpcHandle(conn)
		}
	}()

	// Configure the interface using netlink
	wg.logger.Verbosef("Configuring IP address %s...", wg.IPAddress)
	link, err := netlink.LinkByName(wg.Name)
	if err != nil {
		wg.Close()
		return nil, fmt.Errorf("failed to get netlink interface: %w", err)
	}

	// Parse IP address
	addr, err := netlink.ParseAddr(wg.IPAddress)
	if err != nil {
		wg.Close()
		return nil, fmt.Errorf("failed to parse IP address: %w", err)
	}

	// Set link up
	if err := netlink.LinkSetUp(link); err != nil {
		wg.Close()
		return nil, fmt.Errorf("failed to set link up: %w", err)
	}

	// Add IP address to interface
	if err := netlink.AddrAdd(link, addr); err != nil {
		wg.Close()
		return nil, fmt.Errorf("failed to add IP address: %w", err)
	}

	// Configure WireGuard with keys and peer if specified
	if len(config.Peers) > 0 {
		if err := wg.ConfigureWireGuardDevice(config.Peers); err != nil {
			wg.logger.Errorf("Failed to configure WireGuard: %v", err)
		} else {
			wg.logger.Verbosef("WireGuard configuration applied")
		}
	}

	return wg, nil
}

// configureInterface configures WireGuard device using the UAPI (internal function)
func configureInterface(name string, privateKey string, listenPort int, peers []PeerConfig) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to create wgctrl client: %w", err)
	}
	defer client.Close()

	// Parse private key
	privKey, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}

	// Create device config
	config := wgtypes.Config{
		PrivateKey: &privKey,
	}

	// Add listen port if specified
	if listenPort > 0 {
		config.ListenPort = &listenPort
	}

	// Add peers if provided
	if len(peers) > 0 {
		peerConfigs := make([]wgtypes.PeerConfig, 0, len(peers))

		for _, peer := range peers {
			pubKey, err := wgtypes.ParseKey(peer.PublicKey)
			if err != nil {
				return fmt.Errorf("invalid peer public key: %w", err)
			}

			peerConfig := wgtypes.PeerConfig{
				PublicKey:         pubKey,
				ReplaceAllowedIPs: true,
			}

			// Parse endpoint

			if peer.Endpoint != "" {
				endpoint, err := net.ResolveUDPAddr("udp", peer.Endpoint)
				if err != nil {
					return fmt.Errorf("invalid endpoint address: %w", err)
				}

				peerConfig.Endpoint = endpoint
			}

			// Parse allowed IPs
			if peer.AllowedIPs != "" {
				ips := strings.Split(peer.AllowedIPs, ",")
				allowedIPs := make([]net.IPNet, 0, len(ips))

				for _, ip := range ips {
					_, ipNet, err := net.ParseCIDR(strings.TrimSpace(ip))
					if err != nil {
						return fmt.Errorf("invalid allowed IP address: %w", err)
					}
					allowedIPs = append(allowedIPs, *ipNet)
				}

				peerConfig.AllowedIPs = allowedIPs
			}

			peerConfigs = append(peerConfigs, peerConfig)
		}

		config.Peers = peerConfigs
	}

	// Configure the interface
	return client.ConfigureDevice(name, config)
}

// WireGuardDeviceInfo returns a printable summary of the WireGuard device configuration
func (w *WireGuardDevice) WireGuardDeviceInfo() string {
	var sb strings.Builder
	sb.WriteString("\n=== WireGuard Interface Info ===\n")
	sb.WriteString(fmt.Sprintf("Interface:    %s\n", w.Name))

	sb.WriteString(fmt.Sprintf("IP Address:   %s\n", w.IPAddress))
	sb.WriteString(fmt.Sprintf("Listen Port:  %d\n", w.ListenPort))
	sb.WriteString(fmt.Sprintf("Private Key:  %s\n", w.PrivateKey))
	sb.WriteString(fmt.Sprintf("Public Key:   %s\n", w.PublicKey))
	return sb.String()
}

// WireGuardMain provides the main entry point for using this library programmatically
// It sets up a WireGuard interface based on the provided configuration and blocks until termination.
func WireGuardMain(config WireGuardConfig) (wg *WireGuardDevice, err error) {
	// Validate required parameters
	if config.IPAddress == "" {
		return nil, fmt.Errorf("IP address is required in configuration")
	}

	// Create and configure the WireGuard device
	wg, err = CreateWireGuardDevice(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create WireGuard device: %w", err)
	}
	defer wg.Close()

	// Wait for termination
	wg.WaitShutdown()
	return wg, nil
}
