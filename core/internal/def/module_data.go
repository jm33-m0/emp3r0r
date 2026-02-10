package def

// PortFwdSession represents a port forwarding session
type PortFwdSession struct {
	ID          string `cbor:"1,keyasint"`
	LocalPort   string `cbor:"2,keyasint"`
	RemoteAddr  string `cbor:"3,keyasint"`
	BindAddr    string `cbor:"4,keyasint"`
	AgentTag    string `cbor:"5,keyasint"`
	Description string `cbor:"6,keyasint"`
	Reverse     bool   `cbor:"7,keyasint"`
	Protocol    string `cbor:"8,keyasint"`
}

// ListenerInfo represents an active listener
type ListenerInfo struct {
	ID       string
	Addr     string
	Port     string
	Protocol string
	Status   string
}

// SSHCredential represents harvested SSH credentials
type SSHCredential struct {
	Host     string
	Port     string
	User     string
	Password string
	Key      string
}

// ModuleInfo represents module metadata
type ModuleInfo struct {
	Name     string
	Exec     string
	Platform string
	Author   string
	Date     string
	Comment  string
}
