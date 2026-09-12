package mesh

import (
	"testing"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// TestGatewayPeerRetainsTransport guards that gateway failover keeps the peer's
// advertised transport, not just its IP: a Silent Node must keep dialling the
// gateway over the transport that gateway actually serves.
func TestGatewayPeerRetainsTransport(t *testing.T) {
	setGatewayPeer(def.MeshNodeMeta{})
	t.Cleanup(func() { setGatewayPeer(def.MeshNodeMeta{}) })

	peer := def.MeshNodeMeta{Addr: "10.0.0.9", Distance: 0, P2PPort: 4000, P2PTransport: "smb"}
	if prev := setGatewayPeer(peer); prev != "" {
		t.Fatalf("expected empty previous gateway, got %q", prev)
	}
	if ip := GetGatewayIP(); ip != "10.0.0.9" {
		t.Fatalf("GetGatewayIP() = %q, want 10.0.0.9", ip)
	}
	got := GetGatewayPeer()
	if got.P2PTransport != "smb" || got.P2PPort != 4000 {
		t.Fatalf("gateway descriptor lost transport/port: %+v", got)
	}

	// Replacing the gateway returns the previous address.
	if prev := setGatewayPeer(def.MeshNodeMeta{Addr: "10.0.0.10"}); prev != "10.0.0.9" {
		t.Fatalf("previous gateway = %q, want 10.0.0.9", prev)
	}
	// Clearing it drops the route.
	setGatewayPeer(def.MeshNodeMeta{})
	if ip := GetGatewayIP(); ip != "" {
		t.Fatalf("GetGatewayIP() after clear = %q, want empty", ip)
	}
}

// TestCurrentMetaAdvertisesTransport asserts the gossip payload tells peers
// which transport this node's relay listens on, which is what lets a
// mixed-transport mesh dial correctly.
func TestCurrentMetaAdvertisesTransport(t *testing.T) {
	oldCfg := common.RuntimeConfig
	t.Cleanup(func() { common.RuntimeConfig = oldCfg })
	common.RuntimeConfig = &def.Config{P2PTransport: "smb"}

	oldPort := GetLocalP2PPort()
	t.Cleanup(func() { SetLocalP2PPort(oldPort) })
	SetLocalP2PPort(4321)

	meta := currentMeta()
	if meta.P2PTransport != "smb" {
		t.Errorf("currentMeta().P2PTransport = %q, want smb", meta.P2PTransport)
	}
	if meta.P2PPort != 4321 {
		t.Errorf("currentMeta().P2PPort = %d, want 4321", meta.P2PPort)
	}
}
