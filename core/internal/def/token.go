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
}

// TagAgentToken is the MsgTunData tag for token push from C2 to agent.
const TagAgentToken = "agent_token"

// CapabilityRouter is the capability value that authorises a node to serve
// as a mesh router (accept relay connections via KCP and pipe them to C2).
const CapabilityRouter = "router"

// CapabilityProxy is kept as an alias for backward compat with handler_signing.go.
// New code should use CapabilityRouter.
const CapabilityProxy = CapabilityRouter
