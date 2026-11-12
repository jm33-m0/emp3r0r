package operator

// tun2socks.go — operator-side transparent proxy using sagernet/sing-tun (the
// same library sing-box uses). sing-tun owns the TUN device, the gVisor stack
// and the selective routing (and its cleanup). Only the destination networks
// given with --route are routed into the TUN and proxied through the C2 SOCKS5
// pivot; the operator's default route is never touched.
//
//     target <agent>                # agent to pivot through
//     socks_start 1080              # SOCKS5 pivot on the C2 (WG IP:1080)
//     tun2socks start --route 10.10.0.0/24   # reach agent-side 10.10.0.0/24
//     curl http://10.10.0.5         # routed via the TUN -> pivot -> agent
//     tun2socks stop

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/api/client"
	tun2socks "github.com/jm33-m0/emp3r0r/core/internal/cc/base/tun2socks"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/wireguard"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/spf13/cobra"
)

const (
	defaultTunName   = "emp3r0r0"
	defaultTunAddr   = "10.0.8.1/24"
	defaultTunMTU    = 1500
	defaultSocksPort = 1080
)

// tun2socksInstance tracks one running sing-tun based instance.
type tun2socksInstance struct {
	name      string
	socksAddr string
	engine    *tun2socks.Engine
}

var (
	tun2socksMu        sync.Mutex
	tun2socksInstances = make(map[string]*tun2socksInstance)
)

// Tun2SocksOptions describes one transparent-proxy instance.
type Tun2SocksOptions struct {
	Port     int
	Host     string
	Socks5   string
	Name     string
	Addr     string
	MTU      int
	Routes   []string
	Excludes []string
}

// Tun2SocksState is one running transparent-proxy instance.
type Tun2SocksState struct {
	Name   string `json:"name"`
	Socks5 string `json:"socks5"`
}

// StartTun2Socks creates a TUN and routes opts.Routes through the C2 SOCKS5
// pivot. An empty Host or a zero Port auto-discovers the running pivot.
func StartTun2Socks(opts Tun2SocksOptions) (Tun2SocksState, error) {
	// Destinations to route through the TUN. Required: the default route is
	// intentionally never changed, so without explicit targets nothing would
	// be proxied (and with AutoRoute alone sing-tun would hijack everything).
	routePrefixes := make([]netip.Prefix, 0, len(opts.Routes))
	for _, r := range opts.Routes {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			return Tun2SocksState{}, fmt.Errorf("invalid route %q: %w", r, err)
		}
		routePrefixes = append(routePrefixes, p.Masked())
	}
	if len(routePrefixes) == 0 {
		return Tun2SocksState{}, fmt.Errorf("at least one route prefix is required (for example 10.10.0.0/24); the default route is never modified")
	}

	socksAddr := opts.Socks5
	if socksAddr == "" {
		host := opts.Host
		port := opts.Port
		if host == "" {
			host = socks5ProxyHost()
		}
		if port <= 0 {
			proxies, err := client.ListSocks5Proxies()
			if err != nil {
				return Tun2SocksState{}, fmt.Errorf("query running pivots: %w", err)
			}
			switch len(proxies) {
			case 0:
				return Tun2SocksState{}, fmt.Errorf("no SOCKS5 pivot is running on the C2; start one first")
			case 1:
				port = proxies[0].Port
			default:
				return Tun2SocksState{}, fmt.Errorf("multiple SOCKS5 pivots are running; pick one by port")
			}
		}
		if port <= 0 {
			port = defaultSocksPort
		}
		socksAddr = fmt.Sprintf("%s:%d", host, port)
	}
	tunName := opts.Name
	if tunName == "" {
		tunName = defaultTunName
	}
	addr := opts.Addr
	if addr == "" {
		addr = defaultTunAddr
	}
	mtu := opts.MTU
	if mtu <= 0 {
		mtu = defaultTunMTU
	}

	// The pivot itself must never be routed into the TUN, otherwise the engine
	// would proxy its own SOCKS dials. These are subtracted from --route. The
	// pivot host is added by IP, resolving hostnames too: a hostname that
	// resolves inside a routed prefix would otherwise capture the engine's own
	// SOCKS dials and loop forever.
	prefixes := make([]netip.Prefix, 0, len(opts.Excludes)+1)
	for _, e := range opts.Excludes {
		p, err := netip.ParsePrefix(e)
		if err != nil {
			return Tun2SocksState{}, fmt.Errorf("invalid exclude %q: %w", e, err)
		}
		prefixes = append(prefixes, p.Masked())
	}
	if h, _, err := net.SplitHostPort(socksAddr); err == nil {
		if ip := net.ParseIP(h); ip != nil {
			if addr, ok := netip.AddrFromSlice(ip); ok {
				prefixes = append(prefixes, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
			}
		} else if ips, err := net.LookupIP(h); err == nil {
			for _, ip := range ips {
				if addr, ok := netip.AddrFromSlice(ip); ok {
					addr = addr.Unmap()
					prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
				}
			}
		}
	}

	// Preflight: the pivot must be reachable before we reroute traffic. Dial
	// through the userspace WireGuard stack (the pivot is reached on the C2's
	// tunnel address, not on the host network).
	dialCtx, cancelDial := context.WithTimeout(context.Background(), 3*time.Second)
	conn, err := wireguard.DialContext(dialCtx, "tcp", socksAddr)
	cancelDial()
	if err != nil {
		return Tun2SocksState{}, fmt.Errorf("SOCKS5 pivot at %s is not reachable: %w", socksAddr, err)
	}
	_ = conn.Close()

	tun2socksMu.Lock()
	if _, exists := tun2socksInstances[tunName]; exists {
		tun2socksMu.Unlock()
		return Tun2SocksState{}, fmt.Errorf("tun2socks %q is already running", tunName)
	}
	tun2socksMu.Unlock()

	inet4 := []netip.Prefix{}
	if p, err := netip.ParsePrefix(addr); err == nil {
		inet4 = []netip.Prefix{p}
	} else {
		return Tun2SocksState{}, fmt.Errorf("invalid tun address %q: %w", addr, err)
	}

	eng, err := tun2socks.Start(tun2socks.Config{
		Name:          tunName,
		MTU:           uint32(mtu),
		Inet4Address:  inet4,
		Socks5Addr:    socksAddr,
		Route:         routePrefixes,
		RouteExcludes: prefixes,
		DialContext:   wireguard.DialContext,
		LogTag:        tunName,
	})
	if err != nil {
		return Tun2SocksState{}, fmt.Errorf("start tun2socks: %w", err)
	}

	tun2socksMu.Lock()
	tun2socksInstances[tunName] = &tun2socksInstance{name: tunName, socksAddr: socksAddr, engine: eng}
	tun2socksMu.Unlock()

	return Tun2SocksState{Name: tunName, Socks5: socksAddr}, nil
}

// StopTun2Socks closes one transparent-proxy instance.
func StopTun2Socks(name string) error {
	if name == "" {
		name = defaultTunName
	}
	tun2socksMu.Lock()
	inst, ok := tun2socksInstances[name]
	if ok {
		delete(tun2socksInstances, name)
	}
	tun2socksMu.Unlock()
	if !ok || inst == nil {
		return fmt.Errorf("tun2socks %q is not running", name)
	}
	if err := inst.engine.Close(); err != nil {
		return fmt.Errorf("stop tun2socks %q: %w", name, err)
	}
	return nil
}

// Tun2SocksStatus lists the running transparent-proxy instances.
func Tun2SocksStatus() []Tun2SocksState {
	tun2socksMu.Lock()
	defer tun2socksMu.Unlock()
	out := make([]Tun2SocksState, 0, len(tun2socksInstances))
	for name, inst := range tun2socksInstances {
		out = append(out, Tun2SocksState{Name: name, Socks5: inst.socksAddr})
	}
	return out
}

func tun2socksStartCmdRun(cmd *cobra.Command, _ []string) {
	opts := Tun2SocksOptions{}
	opts.Port, _ = cmd.Flags().GetInt("port")
	opts.Host, _ = cmd.Flags().GetString("host")
	if !cmd.Flags().Changed("port") {
		opts.Port = 0
	}
	if !cmd.Flags().Changed("host") {
		opts.Host = ""
	}
	opts.Socks5, _ = cmd.Flags().GetString("socks5")
	opts.Name, _ = cmd.Flags().GetString("name")
	opts.Addr, _ = cmd.Flags().GetString("addr")
	opts.MTU, _ = cmd.Flags().GetInt("mtu")
	opts.Routes, _ = cmd.Flags().GetStringSlice("route")
	opts.Excludes, _ = cmd.Flags().GetStringSlice("exclude")

	state, err := StartTun2Socks(opts)
	if err != nil {
		logging.Errorf("tun2socks start: %v", err)
		return
	}
	logging.Successf("tun2socks %q started: SOCKS5 %s; routing %v through the TUN (default route untouched)", state.Name, state.Socks5, opts.Routes)
	logging.Warningf("Use `tun2socks stop` to remove routes and the TUN device")
}

func tun2socksStopCmdRun(_ *cobra.Command, args []string) {
	name := defaultTunName
	if len(args) > 0 {
		name = args[0]
	}
	if err := StopTun2Socks(name); err != nil {
		logging.Errorf("tun2socks stop: %v", err)
		return
	}
	logging.Successf("tun2socks %q stopped", name)
}

func tun2socksStatusCmdRun() {
	states := Tun2SocksStatus()
	if len(states) == 0 {
		logging.Infof("No tun2socks instance is running")
		return
	}
	for _, state := range states {
		logging.Infof("tun2socks %q: SOCKS5 %s", state.Name, state.Socks5)
	}
}

// buildTun2SocksCommand assembles the `tun2socks` command tree.
func buildTun2SocksCommand() *cobra.Command {
	root := &cobra.Command{
		Use:     "tun2socks",
		GroupID: "c2",
		Short:   "Route operator traffic to agent-side networks through the selected agent (sing-box tun engine)",
		Example: "target <agent-id>\n  socks_start 1080\n  tun2socks start --route 10.10.0.0/24\n  curl http://10.10.0.5",
	}

	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Create a TUN and proxy TCP to --route networks through the C2 SOCKS5 pivot",
		Long: `Create a TUN device and proxy TCP through the C2 SOCKS5 pivot.

Only the networks given with --route are routed into the TUN (repeatable,
e.g. --route 10.10.0.0/24 --route 192.168.2.0/24). The default route of this
host is never modified, so normal connectivity keeps working. Traffic to the
routed networks is terminated by the gVisor stack and re-opened through the
SOCKS5 pivot, i.e. it appears to originate from the selected agent.`,
		Run: tun2socksStartCmdRun,
	}
	startCmd.Flags().IntP("port", "p", defaultSocksPort, "C2 SOCKS5 pivot port (auto-discovered when omitted)")
	startCmd.Flags().StringP("host", "", wireguard.WgServerIP, "C2 host (WireGuard IP; 127.0.0.1 in local mode)")
	startCmd.Flags().StringP("socks5", "s", "", "Full SOCKS5 address host:port (overrides --host/--port)")
	startCmd.Flags().StringP("name", "n", defaultTunName, "TUN device name")
	startCmd.Flags().StringP("addr", "", defaultTunAddr, "Address assigned to the TUN device (ip/prefix)")
	startCmd.Flags().IntP("mtu", "", defaultTunMTU, "TUN MTU")
	startCmd.Flags().StringSliceP("route", "r", nil, "Destination network routed into the TUN (repeatable), e.g. 10.10.0.0/24; the default route is never changed")
	startCmd.Flags().StringSliceP("exclude", "x", nil, "Subnets subtracted from --route so they stay on the normal path (repeatable)")
	root.AddCommand(startCmd)

	stopCmd := &cobra.Command{
		Use:   "stop [tun-name]",
		Short: "Stop tun2socks (routes and TUN device are removed)",
		Args:  cobra.MaximumNArgs(1),
		Run:   tun2socksStopCmdRun,
	}
	root.AddCommand(stopCmd)

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show running tun2socks instances",
		Run:   func(*cobra.Command, []string) { tun2socksStatusCmdRun() },
	}
	root.AddCommand(statusCmd)

	return root
}
