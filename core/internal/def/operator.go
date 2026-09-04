package def

// Operation is a request sent from the operator to the C2 server
type Operation struct {
	AgentTag string  `cbor:"1,keyasint"` // the target agent
	Action   string  `cbor:"2,keyasint"` // the action to perform
	Command  *string `cbor:"3,keyasint"` // the command to send to the agent
	JobID    *string `cbor:"8,keyasint"` // the job ID (if action is "command")
}

// IsOptionSet checks if a specific option is set
func (op *Operation) IsOptionSet(option string) bool {
	switch option {
	case "command":
		return op.Command != nil
	case "job_id":
		return op.JobID != nil
	default:
		return false
	}
}

// SignRequest is the request to sign data
type SignRequest struct {
	Content []byte `cbor:"1,keyasint"` // content to sign (usually UUID)
}

// OperatorIdleConfig updates server-side operator-idle settings.
type OperatorIdleConfig struct {
	OperatorIdleTimeout int `cbor:"1,keyasint"` // seconds; 0 disables idle-based rejection
}

// FTPStreamRequest is the request to register an FTP stream
type FTPStreamRequest struct {
	Token        string               `cbor:"1,keyasint"`
	FilePath     string               `cbor:"2,keyasint"`
	ExpectedSize int64                `cbor:"3,keyasint"`
	Checksum     string               `cbor:"4,keyasint"`
	Claim        *OperatorStreamClaim `cbor:"5,keyasint"`
}

// Socks5ProxyRequest is the payload used to start/stop a C2-resident SOCKS5
// pivot. The listener accepts operator (WireGuard/VPN) traffic on the C2 host
// and relays every connection through the bound agent via a dedicated C2 stream.
type Socks5ProxyRequest struct {
	AgentTag string `cbor:"1,keyasint"` // relay target agent (start only)
	Port     int    `cbor:"2,keyasint"` // C2 listener port
	BindAddr string `cbor:"3,keyasint"` // C2 bind address; empty = all interfaces
}

// Socks5ProxyStatus describes one running C2-side SOCKS5 pivot.
type Socks5ProxyStatus struct {
	Port     int    `cbor:"1,keyasint"` // C2 listener port
	AgentTag string `cbor:"2,keyasint"` // agent the pivot relays through
	BindAddr string `cbor:"3,keyasint"` // C2 bind address
}
