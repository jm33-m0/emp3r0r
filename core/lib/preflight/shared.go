package preflight

// PreflightRequest payload sent by agent
type PreflightRequest struct {
	AgentUUID    string `json:"uuid"`      // Agent UUID
	AgentUUIDSig []byte `json:"sig"`       // Signature of UUID using AgentKey
	Timestamp    int64  `json:"timestamp"` // Unix timestamp for replay protection
}

// PreflightResponse payload returned by server
type PreflightResponse struct {
	Status      string `json:"status"`      // "OK" or "AC" (Allow Connect)
	Instruction string `json:"instruction"` // Optional instruction
}
