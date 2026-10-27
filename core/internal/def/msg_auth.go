package def

const (
	// MsgAuthType identifies the CBOR envelope and its wire version.
	MsgAuthType = "auth_v2"
)

// MsgAuth is the first-envelope authentication record for a C2 stream.
// All trust decisions are derived from these payload fields, not wrapper metadata.
type MsgAuth struct {
	Type          string `cbor:"11,keyasint"` // must be MsgAuthType
	AgentUUID     string `cbor:"12,keyasint"` // agent identity
	IdentityToken []byte `cbor:"13,keyasint"` // CA-signed proof for AgentUUID
	Timestamp     int64  `cbor:"14,keyasint"` // unix seconds
	Nonce         string `cbor:"15,keyasint"` // anti-replay nonce
	Route         string `cbor:"16,keyasint"` // exactly one configured route name
	AgentProof    []byte `cbor:"17,keyasint"` // agent-key signature over canonical auth string
	StreamID      string `cbor:"19,keyasint"` // optional identifier for a continuous stream (e.g. file transfer token)
}
