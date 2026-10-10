package def

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
