package preflight

// PreflightRequest payload sent by agent
type PreflightRequest struct {
	AgentUUID    string `cbor:"1,keyasint"` // Agent UUID
	AgentUUIDSig []byte `cbor:"2,keyasint"` // Signature of UUID using AgentKey
	Timestamp    int64  `cbor:"3,keyasint"` // Unix timestamp for replay protection
}

// PreflightResponse payload returned by server
type PreflightResponse struct {
	Status      string `cbor:"1,keyasint"` // "OK" or "AC" (Allow Connect)
	Instruction string `cbor:"2,keyasint"` // Optional instruction
}
