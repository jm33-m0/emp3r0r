package def

// MsgAuthType identifies the CBOR envelope used for payload-level auth.
const MsgAuthType = "auth_v1"

// MsgAuth is the first-envelope authentication record for a C2 stream.
// All trust decisions are derived from these payload fields, not wrapper metadata.
type MsgAuth struct {
	Type         string   `cbor:"11,keyasint"` // must be MsgAuthType
	AgentUUID    string   `cbor:"12,keyasint"` // agent identity
	IdentityToken string  `cbor:"13,keyasint"` // CA-signed proof for AgentUUID (base64)
	Timestamp    int64    `cbor:"14,keyasint"` // unix seconds
	Nonce        string   `cbor:"15,keyasint"` // anti-replay nonce
	Capabilities []string `cbor:"16,keyasint"` // optional advertised capabilities
	AgentProof   string   `cbor:"17,keyasint"` // optional agent-key signature over canonical auth string (base64)
	EphemPublicKey []byte `cbor:"18,keyasint"` // optional ephemeral key for early key-exchange workflows
	StreamID       string `cbor:"19,keyasint"` // optional identifier for a continuous stream (e.g. file transfer token)
}