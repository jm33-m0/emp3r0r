package tun

const (
	// WebRoot root path of APIs
	WebRoot = "emp3r0r"

	// CheckInAPI agent send POST to this API to report its system info
	CheckInAPI = WebRoot + "/checkin"

	// MsgAPI duplex tunnel between agent and cc
	MsgAPI = WebRoot + "/msg"

	// ReverseShellAPI duplex tunnel between agent and cc
	ReverseShellAPI = WebRoot + "/rshell"

	// ProxyAPI proxy interface
	ProxyAPI = WebRoot + "/proxy"

	// FTPAPI file transfer
	FTPAPI = WebRoot + "/ftp"

	// FileAPI host some files
	FileAPI = "/www/"
)
