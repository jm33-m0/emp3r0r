package tun

const (
	// CheckInAPI agent send POST to this API to report its system info
	CheckInAPI = "checkin"

	// MsgAPI duplex tunnel between agent and cc
	MsgAPI = "msg"

	// ReverseShellAPI duplex tunnel between agent and cc
	ReverseShellAPI = "rshell"

	// FileAPI host some files
	FileAPI = "www/"
)
