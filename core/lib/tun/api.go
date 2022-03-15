package tun

const (
	// WebRoot root path of APIs
	WebRoot = "3276d367-8400-11ec-9ac4-b9d591256de4"

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
