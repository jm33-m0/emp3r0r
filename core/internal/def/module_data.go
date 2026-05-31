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

// ModuleInfo represents module metadata
type ModuleInfo struct {
	Name     string
	Exec     string
	Platform string
	Author   string
	Date     string
	Comment  string
}
