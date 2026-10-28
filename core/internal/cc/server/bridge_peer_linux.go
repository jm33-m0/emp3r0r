//go:build linux

package server

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// checkBridgePeer verifies that the bridge process runs as the same user as the
// C2. The bridge socket is a local trust boundary; other users must not be able
// to inject streams into it.
func checkBridgePeer(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get bridge socket: %w", err)
	}
	var (
		cred *unix.Ucred
		serr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return fmt.Errorf("inspect bridge peer: %w", err)
	}
	if serr != nil {
		return fmt.Errorf("inspect bridge peer credentials: %w", serr)
	}
	if cred == nil {
		return fmt.Errorf("bridge peer credentials unavailable")
	}
	if int(cred.Uid) != os.Geteuid() {
		return fmt.Errorf("bridge peer uid %d does not match c2 uid %d", cred.Uid, os.Geteuid())
	}
	return nil
}
