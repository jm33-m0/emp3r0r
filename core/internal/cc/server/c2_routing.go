package server

import (
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// GetRouteForService returns the randomized route string for a given service name
func GetRouteForService(service string) string {
	switch service {
	case "checkin":
		return live.RuntimeConfig.C2Routes.Checkin
	case "msg":
		return live.RuntimeConfig.C2Routes.Msg
	case "ftp":
		return live.RuntimeConfig.C2Routes.FTP
	case "www":
		return live.RuntimeConfig.C2Routes.WWW
	case "proxy":
		return live.RuntimeConfig.C2Routes.Proxy
	default:
		return ""
	}
}
