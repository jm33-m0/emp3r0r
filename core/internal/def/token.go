package def

// AgentToken is a signed token issued by C2, granting an agent a specific capability.
// Only agents holding a valid, CA-signed token may serve as mesh routers.
type AgentToken struct {
	AgentID    string `cbor:"1,keyasint"` // Agent UUID
	IP         string `cbor:"2,keyasint"` // Optional IP binding (prevents replay)
	Capability string `cbor:"3,keyasint"` // e.g. CapabilityRouter
	ExpiresAt  int64  `cbor:"4,keyasint"` // Unix timestamp
	Signature  []byte `cbor:"5,keyasint"` // ECDSA sig over AgentID+IP+Capability+ExpiresAt
}

// MeshNodeMeta is the gossip NodeMeta payload.
// Each node advertises its C2-signed token + current routing distance.
// GetAuthorizedPeers sorts by Distance ascending for shortest-path preference.
type MeshNodeMeta struct {
	Token    *AgentToken `cbor:"1,keyasint"` // C2-signed, capability=CapabilityRouter
	Distance int         `cbor:"2,keyasint"` // hops to C2: 0=Gateway, >0=Routed, -1=Unknown
	Addr     string      `cbor:"3,keyasint"` // node address
}

// TagAgentToken is the MsgTunData tag for token push from C2 to agent.
const TagAgentToken = "agent_token"

// TagPeerList is the MsgTunData tag for P2P peer list push from C2 to agent.
const TagPeerList = "peer_list"

// CapabilityRouter is the capability value that authorises a node to serve
// as a mesh router (accept relay connections via KCP and pipe them to C2).
const CapabilityRouter = "router"

// CapabilityProxy is kept as an alias for backward compat with handler_signing.go.
// New code should use CapabilityRouter.
const CapabilityProxy = CapabilityRouter

const (
	// TagFTPRelayDataPrefix marks operator-tunnel frames carrying raw FTP stream chunks.
	TagFTPRelayDataPrefix = "ftp_relay_data:"
	// TagFTPRelayDonePrefix marks end-of-stream for an FTP relay token.
	TagFTPRelayDonePrefix = "ftp_relay_done:"
	// TagFTPRelayErrorPrefix marks a stream relay error for a token.
	TagFTPRelayErrorPrefix = "ftp_relay_error:"

	TagProxyRelayDataPrefix  = "proxy_relay_data:"
	TagProxyRelayBackPrefix  = "proxy_relay_back:"
	TagProxyRelayDonePrefix  = "proxy_relay_done:"
	TagProxyRelayErrorPrefix = "proxy_relay_error:"

	TagWWWRelayRequestPrefix = "www_relay_request:"
	TagWWWRelayDataPrefix    = "www_relay_data:"
	TagWWWRelayDonePrefix    = "www_relay_done:"
	TagWWWRelayErrorPrefix   = "www_relay_error:"
)

// Operator stream capabilities for claim-scoped authorization.
const (
	OperatorCapabilityRegisterPortFwd = "register_portfwd"
	OperatorCapabilityRegisterFTP     = "register_ftp"
)

// OperatorStreamClaim is a signed, short-lived claim used by operators to
// authorize stream registration actions.
type OperatorStreamClaim struct {
	OperatorSession string `cbor:"1,keyasint"` // operator session id
	StreamID        string `cbor:"2,keyasint"` // stream/session id bound to this claim
	Capability      string `cbor:"3,keyasint"` // one of OperatorCapability*
	IssuedAt        int64  `cbor:"4,keyasint"` // unix timestamp
	ExpiresAt       int64  `cbor:"5,keyasint"` // unix timestamp
	Nonce           string `cbor:"6,keyasint"` // replay protection nonce
	Signature       []byte `cbor:"7,keyasint"` // ECDSA signature over canonical claim string
}
