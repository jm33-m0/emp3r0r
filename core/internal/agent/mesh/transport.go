package mesh

// transport.go — pluggable transport interface for mesh peer connections.
//
// MeshTransport abstracts dialling a peer's relay. The default implementation,
// RegistryTransport, resolves the *peer's* advertised transport (kcp/mtls/smb)
// from the gossip metadata and dials it via transport.PeerEndpoint, so a mixed
// mesh does not assume every peer runs the local default transport.

import (
	"context"
	"net"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// MeshTransport is the interface for dialling a mesh Gateway peer.
// Dial returns a net.Conn representing a transparent pipe to the C2 server.
type MeshTransport interface {
	Dial(ctx context.Context, peer def.MeshNodeMeta) (net.Conn, error)
	Ping(ctx context.Context, peer def.MeshNodeMeta) error
}

// RegistryTransport dials a peer using the transport advertised in its gossip
// metadata, falling back to the locally configured transport only when the peer
// advertised none.
type RegistryTransport struct{}

func (RegistryTransport) Dial(ctx context.Context, peer def.MeshNodeMeta) (net.Conn, error) {
	return DialGatewayPeer(ctx, peer, OpcodeConnectC2)
}

func (RegistryTransport) Ping(ctx context.Context, peer def.MeshNodeMeta) error {
	conn, err := DialGatewayPeer(ctx, peer, OpcodePing)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}
