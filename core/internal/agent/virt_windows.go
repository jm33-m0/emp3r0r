//go:build windows
// +build windows

package agent

// CheckContainer are we in a container? what container is it?
func crossPlatformCheckContainer() (product string) {
	product = "None"
	return
}
