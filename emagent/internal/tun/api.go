package tun

const (
	// CheckInAPI agent send POST to this API to report its system info
	CheckInAPI = "checkin"

	// TunAPI duplex tunnel between agent and cc
	TunAPI = "tun"

	// StreamAPI duplex tunnel between agent and cc
	StreamAPI = "stream"

	// FileAPI host some files
	FileAPI = "www/"
)
