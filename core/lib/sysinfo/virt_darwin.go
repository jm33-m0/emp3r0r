//go:build darwin
// +build darwin

package sysinfo

// CheckContainer are we in a container? what container is it?
func CheckContainer() (product string) {
	return "Not implemented on darwin"
}
