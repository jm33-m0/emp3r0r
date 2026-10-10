package wireguard

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
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

	// persistentKeepalive keeps NAT mappings alive between the two peers.
	persistentKeepalive = 25 * time.Second
)

var (
	WgServerIP   = "172.16.254.1" // server's static WireGuard IP
	WgOperatorIP = "172.16.254.2" // operator's static WireGuard IP

	WgServer   *WireGuardDevice // server's WireGuard device
	WgOperator *WireGuardDevice // operator's WireGuard device
)

// WireGuardDevice is a fully userspace WireGuard interface. Its TCP/IP stack
// is provided by gVisor (via wireguard-go's tun/netstack), so it needs neither
// a kernel TUN device nor netlink and therefore no elevated privileges. Only
// the owning process can reach the tunnel addresses; use DialContext/Listen to
// route traffic through it.
type WireGuardDevice struct {
	// Name is a human readable label (the userspace stack has no OS interface)
	Name string
	// IPAddress is the tunnel address with CIDR (e.g. "192.168.2.1/24")
	IPAddress string
	// PrivateKey is the WireGuard private key (base64)
	PrivateKey string
	// PublicKey is derived from PrivateKey
	PublicKey string
	// ListenPort is the UDP port the WireGuard transport listens on
	ListenPort int
	// LogLevel is the verbosity of the WireGuard logger
	LogLevel LogLevel
	// Context is cancelled when the device is closed
	Context context.Context
	// Cancel cancels Context
	Cancel context.CancelFunc

	device *device.Device
	tun    tun.Device
	tnet   *netstack.Net
	logger *device.Logger

	// subnet is the tunnel network derived from IPAddress; it decides whether
	// an outbound dial belongs on the userspace stack.
	subnet *net.IPNet
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
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}
	return key.String(), nil
}

// PublicKeyFromPrivate derives the public key from a private key
func PublicKeyFromPrivate(privateKey string) (string, error) {
	key, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}
	return key.PublicKey().String(), nil
}

// Close shuts down the WireGuard device and releases its resources. It is safe
// to call more than once.
func (w *WireGuardDevice) Close() {
	if w.Cancel != nil {
		w.Cancel()
	}
	if w.device != nil {
		// device.Close also closes the underlying tun, so it must not be
		// closed separately (netstack channels would be double closed). It is
		// idempotent, so the field is intentionally left intact to keep Wait
		// race-free.
		w.device.Close()
	}
}

// Wait blocks until the device is closed.
func (w *WireGuardDevice) Wait() {
	if w.device == nil {
		return
	}
	select {
	case <-w.device.Wait():
	case <-w.Context.Done():
	}
}

// ConfigureWireGuardDevice applies the given peers (and the device's key and
// listen port) to a running device.
func (w *WireGuardDevice) ConfigureWireGuardDevice(peers []PeerConfig) error {
	if w.device == nil {
		return errors.New("wireguard: device is not initialized")
	}
	uapi, err := buildUAPIConfig(w.PrivateKey, w.ListenPort, peers)
	if err != nil {
		return err
	}
	if err := w.device.IpcSet(uapi); err != nil {
		return fmt.Errorf("apply WireGuard configuration: %w", err)
	}
	return nil
}

// DialContext opens a connection through the userspace stack.
func (w *WireGuardDevice) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if w.tnet == nil {
		return nil, errors.New("wireguard: device is not initialized")
	}
	return w.tnet.DialContext(ctx, network, address)
}

// Listen creates a TCP listener on the userspace stack.
func (w *WireGuardDevice) Listen(network, address string) (net.Listener, error) {
	if w.tnet == nil {
		return nil, errors.New("wireguard: device is not initialized")
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
		addr, err := net.ResolveTCPAddr(network, address)
		if err != nil {
			return nil, err
		}
		return w.tnet.ListenTCP(addr)
	default:
		return nil, fmt.Errorf("wireguard: unsupported listen network %q", network)
	}
}

// Contains reports whether address belongs to this device's tunnel subnet.
func (w *WireGuardDevice) Contains(address string) bool {
	if w.subnet == nil {
		return false
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	return ip != nil && w.subnet.Contains(ip)
}

// CreateWireGuardDevice creates and configures a userspace WireGuard device.
func CreateWireGuardDevice(config WireGuardConfig) (*WireGuardDevice, error) {
	var err error
	wg := &WireGuardDevice{
		Name:       config.InterfaceName,
		IPAddress:  config.IPAddress,
		PrivateKey: config.PrivateKey,
		ListenPort: config.ListenPort,
		LogLevel:   config.LogLevel,
	}

	wg.Context, wg.Cancel = context.WithCancel(context.Background())

	// Validate the tunnel address and remember the subnet for DialContext.
	// A single CIDR parse provides both the interface address and its network.
	localIP, ipnet, err := net.ParseCIDR(config.IPAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address format: %w", err)
	}
	wg.subnet = ipnet
	localAddr, ok := netip.AddrFromSlice(localIP)
	if !ok {
		return nil, fmt.Errorf("invalid IP address format: %q", config.IPAddress)
	}
	// net.ParseCIDR may return a 16-byte IPv4-mapped address; unmap so the
	// netstack enables the IPv4 protocol (Is4 must be true).
	localAddr = localAddr.Unmap()

	wg.logger = device.NewLogger(int(config.LogLevel), fmt.Sprintf("(%s) ", config.InterfaceName))

	if wg.PrivateKey == "" {
		wg.PrivateKey, err = GeneratePrivateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
		wg.logger.Verbosef("Generated private key")
	}

	wg.PublicKey, err = PublicKeyFromPrivate(wg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	// Build the userspace gVisor stack. There is no kernel interface and the
	// stack routes every outbound packet into the WireGuard device, which then
	// drops anything outside the configured allowed IPs.
	wg.logger.Verbosef("Creating userspace interface %s...", wg.Name)
	wg.tun, wg.tnet, err = netstack.CreateNetTUN([]netip.Addr{localAddr}, nil, device.DefaultMTU)
	if err != nil {
		wg.Close()
		return nil, fmt.Errorf("failed to create userspace netstack: %w", err)
	}

	wg.device = device.NewDevice(wg.tun, conn.NewDefaultBind(), wg.logger)

	uapi, err := buildUAPIConfig(wg.PrivateKey, wg.ListenPort, config.Peers)
	if err != nil {
		wg.Close()
		return nil, err
	}
	if err = wg.device.IpcSet(uapi); err != nil {
		wg.Close()
		return nil, fmt.Errorf("failed to configure WireGuard device: %w", err)
	}
	if err = wg.device.Up(); err != nil {
		wg.Close()
		return nil, fmt.Errorf("failed to bring WireGuard device up: %w", err)
	}
	wg.logger.Verbosef("WireGuard userspace device started")

	return wg, nil
}

// Listen creates a listener for server-side services. When a userspace
// server device is active the listener lives on its gVisor stack; otherwise
// (e.g. in tests or local mode) it falls back to the host network.
func Listen(network, address string) (net.Listener, error) {
	if WgServer != nil {
		return WgServer.Listen(network, address)
	}
	return net.Listen(network, address)
}

// DialContext dials through the operator userspace stack when the destination
// belongs to the WireGuard tunnel, and through the host network otherwise.
func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if WgOperator != nil && WgOperator.Contains(address) {
		return WgOperator.DialContext(ctx, network, address)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}

// buildUAPIConfig renders the WireGuard UAPI "set" payload used to configure a
// userspace device. Keys are hex-encoded as the UAPI requires.
func buildUAPIConfig(privateKey string, listenPort int, peers []PeerConfig) (string, error) {
	privKey, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "private_key=%s\n", hex.EncodeToString(privKey[:]))
	if listenPort > 0 {
		fmt.Fprintf(&sb, "listen_port=%d\n", listenPort)
	}
	sb.WriteString("replace_peers=true\n")

	for _, peer := range peers {
		pubKey, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			return "", fmt.Errorf("invalid peer public key: %w", err)
		}
		fmt.Fprintf(&sb, "public_key=%s\n", hex.EncodeToString(pubKey[:]))
		sb.WriteString("replace_allowed_ips=true\n")

		for _, cidr := range strings.Split(peer.AllowedIPs, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return "", fmt.Errorf("invalid allowed IP address %q: %w", cidr, err)
			}
			fmt.Fprintf(&sb, "allowed_ip=%s\n", cidr)
		}

		if peer.Endpoint != "" {
			endpoint, err := net.ResolveUDPAddr("udp", peer.Endpoint)
			if err != nil {
				return "", fmt.Errorf("invalid endpoint address %q: %w", peer.Endpoint, err)
			}
			fmt.Fprintf(&sb, "endpoint=%s\n", endpoint.String())
		}

		fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n", int(persistentKeepalive.Seconds()))
	}

	return sb.String(), nil
}
