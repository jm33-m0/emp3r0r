//go:build !no_mesh && no_kcp

package transport

import "testing"

// TestMeshTransportsWithoutKCP pins the P2P-on / no-KCP build shape: the mesh
// is a core feature and must keep working through its mTLS and SMB relays,
// while KCP is compiled out.
func TestMeshTransportsWithoutKCP(t *testing.T) {
	names := AllTransportNames()
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		seen[n] = true
		if n == "kcp" {
			t.Errorf("kcp transport registered in a no_kcp build: %v", names)
		}
	}
	for _, want := range []string{"mtls", "smb"} {
		if !seen[want] {
			t.Errorf("mesh transport %q missing in P2P-on/no-KCP build: %v", want, names)
		}
	}
}
