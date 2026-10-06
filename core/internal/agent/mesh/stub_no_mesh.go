//go:build no_mesh

// Package mesh is the stub form of the P2P mesh stack used when the build
// excludes memberlist gossip (tag "no_mesh"). cmd/agent and the command
// handlers still reference the mesh API, so keep the surface identical and
// make every operation a safe no-op.
package mesh

import (
	"context"
	"fmt"
	"net"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

// OpcodeConnectC2 mirrors the real bridge opcode so call sites compile.
const OpcodeConnectC2 byte = 0x01

// GatewayDeadCh is never signalled in a no-mesh build.
var GatewayDeadCh = make(chan struct{}, 1)

func Start(ctx context.Context) {}

func UpdateGossipMeta() {}

func Join(peers []string) {}

func WaitForRoute() string { return "" }

func GetGatewayIP() string { return "" }

func GetGatewayPeer() def.MeshNodeMeta { return def.MeshNodeMeta{} }

func DialGatewayPeer(ctx context.Context, peer def.MeshNodeMeta, opcode byte) (net.Conn, error) {
	return nil, fmt.Errorf("mesh support is not compiled into this agent")
}

func GetPeersForFile(fileName string) map[string]transport.PeerEndpoint { return nil }
