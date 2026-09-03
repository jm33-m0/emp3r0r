// Package tun2socks is an operator-side transparent proxy engine built on
// sagernet/sing-tun (the library sing-box uses). sing-tun owns the TUN
// device, the gVisor stack and the selective routing (and its cleanup); this
// package only supplies the Handler that dials every proxied TCP connection
// through the C2-resident SOCKS5 pivot started with `socks_start`. Only the
// prefixes given in Config.Route are routed into the TUN (sing-box's
// `route_address` mode): the host's default route is never modified, so the
// rest of the connectivity is left untouched.
// It is intentionally independent of the operator console so other cc
// components can start instances programmatically.
//
// The gVisor stack is compiled in with the `with_gvisor` build tag (see
// core/build.py, which builds the operator console with it); without the tag
// sing-tun cannot provide the user-space TCP stack tun2socks is built on and
// Start returns an error instead.
package tun2socks

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime/debug"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
)

// Config configures a tun2socks instance.
type Config struct {
	// Name of the TUN device (default "emp3r0r0").
	Name string
	// MTU of the TUN device (default 1500).
	MTU uint32
	// Inet4Address assigned to the TUN device (default 10.0.8.1/24).
	Inet4Address []netip.Prefix
	// Socks5Addr is the C2 SOCKS5 pivot (host:port) every connection is
	// relayed through. Reachable over the WireGuard network.
	Socks5Addr string
	// Route is the destination network(s) that are routed through the TUN
	// device (sing-tun's Inet4RouteAddress, i.e. sing-box's route_address).
	// Only traffic to these prefixes enters the TUN; the host's default
	// route is never modified, so the rest of the connectivity is left
	// untouched. At least one prefix is required.
	Route []netip.Prefix
	// RouteExcludes are networks subtracted from Route so they always stay
	// on the normal path (typically the SOCKS5 pivot host — capturing it
	// would make the engine proxy its own dials). Loopback is excluded by
	// the kernel automatically.
	RouteExcludes []netip.Prefix
	// LogTag prefixes log lines (default "tun2socks").
	LogTag string
}

func (c *Config) withDefaults() Config {
	if c == nil {
		c = &Config{}
	}
	cfg := *c
	if cfg.Name == "" {
		cfg.Name = "emp3r0r0"
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1500
	}
	if len(cfg.Inet4Address) == 0 {
		cfg.Inet4Address = []netip.Prefix{netip.MustParsePrefix("10.0.8.1/24")}
	}
	if cfg.LogTag == "" {
		cfg.LogTag = "tun2socks"
	}
	return cfg
}

// Engine is a running sing-tun based tun2socks instance.
type Engine struct {
	cfg            Config
	device         tun.Tun
	stack          tun.Stack
	handler        *pivotHandler
	networkMonitor tun.NetworkUpdateMonitor
	monitor        tun.DefaultInterfaceMonitor
	cancel         context.CancelFunc
}

// Start creates the TUN device, brings up the gVisor stack and starts
// forwarding TCP to the given SOCKS5 pivot. Only cfg.Route destinations are
// routed into the TUN (via sing-tun's selective routing); the host's default
// route is never changed. Requires root/CAP_NET_ADMIN (/dev/net/tun).
//
// A network/interface monitor is mandatory: sing-tun's Tun.Start() calls
// Options.InterfaceMonitor.RegisterMyInterface() (and the routing code uses
// the interface finder), so leaving them nil panics as soon as the TUN
// device is brought up. UDPTimeout/ICMPTimeout must be non-zero as well,
// otherwise sing-tun's NewUDPNat panics with "invalid timeout".
//
// sing-tun is defensive about none of this and panics on bad input instead
// of returning an error; Start recovers any synchronous panic and returns it
// as an error so the caller (the operator console) is not killed.
func Start(cfg Config) (eng *Engine, err error) {
	defer func() {
		if r := recover(); r != nil {
			eng = nil
			err = fmt.Errorf("tun2socks[%s]: panic during start: %v\n%s", cfg.LogTag, r, debug.Stack())
		}
	}()

	cfg = cfg.withDefaults()
	if cfg.Socks5Addr == "" {
		return nil, fmt.Errorf("tun2socks: SOCKS5 pivot address is required")
	}
	if len(cfg.Route) == 0 {
		return nil, fmt.Errorf("tun2socks: no destination to route through the TUN — set Route (CLI: --route 10.10.0.0/24); the default route is intentionally never touched")
	}

	// Masked, deduplicated set of destinations that may enter the TUN.
	route := make([]netip.Prefix, 0, len(cfg.Route))
	seen := make(map[netip.Prefix]bool, len(cfg.Route))
	for _, p := range cfg.Route {
		if !p.IsValid() {
			return nil, fmt.Errorf("tun2socks: invalid route prefix %q", p)
		}
		p = p.Masked()
		if seen[p] {
			continue
		}
		seen[p] = true
		route = append(route, p)
	}
	excludes := make([]netip.Prefix, 0, len(cfg.RouteExcludes))
	for _, p := range cfg.RouteExcludes {
		if p.IsValid() {
			excludes = append(excludes, p.Masked())
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	logger := &singLogger{tag: cfg.LogTag}

	fail := func(err error) (*Engine, error) {
		cancel()
		return nil, fmt.Errorf("tun2socks[%s]: %w", cfg.LogTag, err)
	}

	// Create and start the monitors first so both the interface finder is
	// populated and the TUN interface is tracked before routes are set.
	interfaceFinder := control.NewDefaultInterfaceFinder()
	networkMonitor, err := tun.NewNetworkUpdateMonitor(logger)
	if err != nil {
		return fail(fmt.Errorf("create network monitor: %w", err))
	}
	if err = networkMonitor.Start(); err != nil {
		return fail(fmt.Errorf("start network monitor: %w", err))
	}
	interfaceMonitor, err := tun.NewDefaultInterfaceMonitor(networkMonitor, logger, tun.DefaultInterfaceMonitorOptions{
		InterfaceFinder: interfaceFinder,
	})
	if err != nil {
		_ = networkMonitor.Close()
		return fail(fmt.Errorf("create interface monitor: %w", err))
	}
	if err = interfaceMonitor.Start(); err != nil {
		_ = networkMonitor.Close()
		return fail(fmt.Errorf("start interface monitor: %w", err))
	}
	stopMonitors := func() {
		_ = interfaceMonitor.Close()
		_ = networkMonitor.Close()
	}

	opts := tun.Options{
		Name:                     cfg.Name,
		MTU:                      cfg.MTU,
		Inet4Address:             cfg.Inet4Address,
		AutoRoute:                true,
		DNSMode:                  tun.DNSModeDisabled,
		Inet4RouteAddress:        route,
		Inet4RouteExcludeAddress: excludes,
		InterfaceFinder:          interfaceFinder,
		InterfaceMonitor:         interfaceMonitor,
		IPRoute2TableIndex:       tun.DefaultIPRoute2TableIndex,
		IPRoute2RuleIndex:        tun.DefaultIPRoute2RuleIndex,
		Logger:                   logger,
	}

	device, err := tun.New(opts)
	if err != nil {
		stopMonitors()
		return fail(fmt.Errorf("create tun: %w", err))
	}
	if err = device.Start(); err != nil {
		_ = device.Close()
		stopMonitors()
		return fail(fmt.Errorf("start tun: %w", err))
	}

	handler := newPivotHandler(cfg.Socks5Addr, cfg.LogTag)
	stack, err := tun.NewStack("gvisor", tun.StackOptions{
		Context:         ctx,
		Tun:             device,
		TunOptions:      opts,
		Handler:         handler,
		Logger:          logger,
		InterfaceFinder: interfaceFinder,
		// Non-zero timeouts: sing-tun's NewUDPNat panics with "invalid
		// timeout" when UDPTimeout is 0.
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Minute,
	})
	if err != nil {
		_ = device.Close()
		stopMonitors()
		return fail(fmt.Errorf("new gvisor stack (rebuild the operator console with `-tags with_gvisor`): %w", err))
	}
	if err = stack.Start(); err != nil {
		_ = device.Close()
		stopMonitors()
		return fail(fmt.Errorf("start gvisor stack: %w", err))
	}

	logging.Infof("tun2socks[%s]: started, SOCKS5 %s; routing ONLY %v through %s (default route untouched)", cfg.LogTag, cfg.Socks5Addr, route, cfg.Name)
	return &Engine{
		cfg:            cfg,
		device:         device,
		stack:          stack,
		handler:        handler,
		networkMonitor: networkMonitor,
		monitor:        interfaceMonitor,
		cancel:         cancel,
	}, nil
}

// Close stops the stack and the TUN device, then the interface monitors.
// sing-tun removes the routes, rules and the device itself, so nothing
// lingers after shutdown. Like Start, Close recovers panics from sing-tun
// and reports them as errors instead of killing the process.
func (e *Engine) Close() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.Join(err, fmt.Errorf("tun2socks[%s]: panic during close: %v\n%s", e.cfg.LogTag, r, debug.Stack()))
		}
	}()

	var errs []error
	if e.stack != nil {
		if err := e.stack.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close stack: %w", err))
		}
	}
	if e.device != nil {
		if err := e.device.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close tun: %w", err))
		}
	}
	if e.monitor != nil {
		if err := e.monitor.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close interface monitor: %w", err))
		}
	}
	if e.networkMonitor != nil {
		if err := e.networkMonitor.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close network monitor: %w", err))
		}
	}
	e.cancel()
	logging.Infof("tun2socks[%s]: stopped (routes and device cleaned up)", e.cfg.LogTag)
	return errors.Join(errs...)
}
