//go:build !windows

package transport

// smb_pipe_other.go — non-Windows stub for the SMB P2P transport.
//
// SMB peer-to-peer in mainstream C2s is built on Windows named pipes, which
// have no equivalent on Linux/macOS. The mesh stack falls back to kcp or mtls
// when the configured transport is unavailable, so this stub reports a clear
// error instead of failing silently.

import (
	"errors"
	"fmt"
	"net"
)

// ErrSMBNotSupported is returned when the SMB transport is used on a platform
// without the Windows named-pipe / SMB redirector stack.
var ErrSMBNotSupported = errors.New("smb transport is only supported on Windows")

func smbDialPipe(host string, port int, password, salt string) (net.Conn, error) {
	return nil, fmt.Errorf("smb dial %s:%d: %w", host, port, ErrSMBNotSupported)
}

func smbListenPipe(port int, password, salt string) (net.Listener, error) {
	return nil, fmt.Errorf("smb listen port %d: %w", port, ErrSMBNotSupported)
}
