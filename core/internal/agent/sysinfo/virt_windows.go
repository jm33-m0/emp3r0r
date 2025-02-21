//go:build windows
// +build windows

package sysinfo

// CheckContainer are we in a container? what container is it?
func CheckContainer() (product string) {
	product = "Not supported on Windows"
	return
}
