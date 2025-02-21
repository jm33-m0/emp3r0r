//go:build darwin
// +build darwin

package agent

// CheckContainer are we in a container? what container is it?
func crossPlatformCheckContainer() (product string) {
	return "Not implemented on darwin"
}
