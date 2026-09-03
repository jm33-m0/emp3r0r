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

func tun2socksStartCmdRun(cmd *cobra.Command, _ []string) {
	port, _ := cmd.Flags().GetInt("port")
	host, _ := cmd.Flags().GetString("host")
	override, _ := cmd.Flags().GetString("socks5")
	tunName, _ := cmd.Flags().GetString("name")
	addr, _ := cmd.Flags().GetString("addr")
	mtu, _ := cmd.Flags().GetInt("mtu")
	routes, _ := cmd.Flags().GetStringSlice("route")
	excludes, _ := cmd.Flags().GetStringSlice("exclude")

	// Destinations to route through the TUN. Required: the default route is
	// intentionally never changed, so without explicit targets nothing would
	// be proxied (and with AutoRoute alone sing-tun would hijack everything).
	routePrefixes := make([]netip.Prefix, 0, len(routes))
	for _, r := range routes {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			logging.Errorf("tun2socks: invalid --route %q: %v", r, err)
			return
		}
		routePrefixes = append(routePrefixes, p.Masked())
	}
	if len(routePrefixes) == 0 {
		logging.Errorf("tun2socks: specify at least one --route prefix (e.g. `tun2socks start --route 10.10.0.0/24`); the default route is never modified")
		return
	}

	socksAddr := override
	if socksAddr == "" {
		if !cmd.Flags().Changed("host") {
			host = socks5ProxyHost()
		}
		if !cmd.Flags().Changed("port") {
			proxies, err := client.ListSocks5Proxies()
			if err != nil {
				logging.Errorf("tun2socks: query running pivots: %v", err)
				return
			}
			switch len(proxies) {
			case 0:
				logging.Errorf("tun2socks: no SOCKS5 pivot is running on the C2 — run `socks_start <port>` on the target agent first")
				return
			case 1:
				port = proxies[0].Port
				logging.Infof("tun2socks: auto-using running pivot on port %d (agent %s)", proxies[0].Port, proxies[0].AgentTag)
			default:
				logging.Errorf("tun2socks: multiple SOCKS5 pivots are running; pick one with --port")
				return
			}
		}
		if port <= 0 {
			port = defaultSocksPort
		}
		socksAddr = fmt.Sprintf("%s:%d", host, port)
	}
	if tunName == "" {
		tunName = defaultTunName
	}
	if addr == "" {
		addr = defaultTunAddr
	}
	if mtu <= 0 {
		mtu = defaultTunMTU
	}

	// The pivot itself must never be routed into the TUN, otherwise the engine
	// would proxy its own SOCKS dials. These are subtracted from --route.
	prefixes := make([]netip.Prefix, 0, len(excludes)+1)
	for _, e := range excludes {
		p, err := netip.ParsePrefix(e)
		if err != nil {
			logging.Errorf("tun2socks: invalid --exclude %q: %v", e, err)
			return
		}
		prefixes = append(prefixes, p.Masked())
	}
	if h, _, err := net.SplitHostPort(socksAddr); err == nil {
		if ip := net.ParseIP(h); ip != nil {
			prefixes = append(prefixes, netip.PrefixFrom(netip.MustParseAddr(h), 32).Masked())
		}
	}

	// Preflight: the pivot must be reachable before we reroute traffic.
	conn, err := net.DialTimeout("tcp", socksAddr, 3*time.Second)
	if err != nil {
		logging.Errorf("SOCKS5 pivot at %s is not reachable (run `socks_start` first): %v", socksAddr, err)
		return
	}
	_ = conn.Close()

	tun2socksMu.Lock()
	if _, exists := tun2socksInstances[tunName]; exists {
		tun2socksMu.Unlock()
		logging.Errorf("tun2socks %q is already running", tunName)
		return
	}
	tun2socksMu.Unlock()

	inet4 := []netip.Prefix{}
	if p, err := netip.ParsePrefix(addr); err == nil {
		inet4 = []netip.Prefix{p}
	} else {
		logging.Errorf("tun2socks: invalid tun address %q: %v", addr, err)
		return
	}

	eng, err := tun2socks.Start(tun2socks.Config{
		Name:          tunName,
		MTU:           uint32(mtu),
		Inet4Address:  inet4,
		Socks5Addr:    socksAddr,
		Route:         routePrefixes,
		RouteExcludes: prefixes,
		LogTag:        tunName,
	})
	if err != nil {
		logging.Errorf("tun2socks start: %v", err)
		return
	}

	tun2socksMu.Lock()
	tun2socksInstances[tunName] = &tun2socksInstance{name: tunName, socksAddr: socksAddr, engine: eng}
	tun2socksMu.Unlock()

	logging.Successf("tun2socks %q started: SOCKS5 %s, tun %s; routing %v through the TUN (default route untouched)", tunName, socksAddr, addr, routePrefixes)
	logging.Warningf("Use `tun2socks stop` to remove routes and the TUN device")
}

func tun2socksStopCmdRun(cmd *cobra.Command, args []string) {
	tunName := defaultTunName
	if len(args) > 0 {
		tunName = args[0]
	}
	tun2socksMu.Lock()
	inst, ok := tun2socksInstances[tunName]
	if ok {
		delete(tun2socksInstances, tunName)
	}
	tun2socksMu.Unlock()
	if !ok || inst == nil {
		logging.Errorf("tun2socks %q is not running", tunName)
		return
	}
	if err := inst.engine.Close(); err != nil {
		logging.Errorf("tun2socks stop: %v", err)
	}
}

func tun2socksStatusCmdRun(cmd *cobra.Command, _ []string) {
	tun2socksMu.Lock()
	defer tun2socksMu.Unlock()
	if len(tun2socksInstances) == 0 {
		logging.Infof("No tun2socks instance is running")
		return
	}
	for name, inst := range tun2socksInstances {
		logging.Infof("tun2socks %q: SOCKS5 %s", name, inst.socksAddr)
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
		Run:   func(*cobra.Command, []string) { tun2socksStatusCmdRun(nil, nil) },
	}
	root.AddCommand(statusCmd)

	return root
}
