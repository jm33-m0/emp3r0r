package agent

// OSInfo information.
type OSInfo struct {
	Name         string `json:"name,omitempty"`
	Vendor       string `json:"vendor,omitempty"`
	Version      string `json:"version,omitempty"`
	Release      string `json:"release,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	Kernel       string `json:"kernel,omitempty"`
}

func GetOSInfo() *OSInfo {
	return crossPlatformGetOSInfo()
}
