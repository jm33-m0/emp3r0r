//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

package netutil

// IPr works like `ip r` (Dummy)
func IPr() (routes []string) {
	return []string{"N/A"}
}

// IPNeigh works like `ip neigh` (Dummy)
func IPNeigh() []string {
	return []string{"N/A"}
}
