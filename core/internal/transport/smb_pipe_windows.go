//go:build windows

package transport

// smb_pipe_windows.go — Windows named-pipe engine for the SMB P2P transport.
//
// The pipe handles are created with FILE_FLAG_OVERLAPPED so that os.NewFile
// registers them with the Go runtime poller. That gives real SetDeadline
// support (verified on Go 1.26) without any hand-rolled overlapped I/O in the
// read/write path: os.File handles partial reads/writes and ERROR_BROKEN_PIPE
// -> io.EOF for us. Only the initial ConnectNamedPipe is done manually, since
// it has no os.File equivalent.

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"golang.org/x/sys/windows"
)

const (
	smbPipeBufSize = 64 * 1024
)

// smbSupported reports that the Windows named-pipe engine is available.
func smbSupported() bool { return true }

type pipeAddr string

func (a pipeAddr) Network() string { return "smb" }
func (a pipeAddr) String() string  { return string(a) }

// pipeConn is a net.Conn backed by a named-pipe handle. *os.File provides
// Read/Write/Close and deadline support; we only add meaningful addresses.
type pipeConn struct {
	*os.File
	localAddr  net.Addr
	remoteAddr net.Addr
}

func newPipeConn(h windows.Handle, local, remote string) *pipeConn {
	return &pipeConn{
		File:       os.NewFile(uintptr(h), local),
		localAddr:  pipeAddr(local),
		remoteAddr: pipeAddr(remote),
	}
}

func (c *pipeConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *pipeConn) RemoteAddr() net.Addr { return c.remoteAddr }

// smbListenPipe creates a named pipe and returns a listener that accepts one
// connection per pipe instance.
func smbListenPipe(port int, password, salt string) (net.Listener, error) {
	name := `\\.\pipe\` + smbPipeBase(password, salt, port)
	l := &smbPipeListener{
		name:   name,
		closed: make(chan struct{}),
		connCh: make(chan net.Conn),
		refill: make(chan struct{}, 1),
	}

	// Seed one instance synchronously so a peer that dials immediately after
	// discovering our port finds the pipe already present.
	if err := l.startConnector(); err != nil {
		return nil, fmt.Errorf("smb listen %s: %w", name, err)
	}
	go l.refillLoop()
	return l, nil
}

// smbPipeListener keeps exactly one idle pipe instance pending at a time and
// replenishes it after every accepted connection.
type smbPipeListener struct {
	name      string
	closed    chan struct{}
	closeOnce sync.Once
	connCh    chan net.Conn
	refill    chan struct{}
}

func (l *smbPipeListener) Addr() net.Addr { return pipeAddr(l.name) }

// Accept returns the next connected peer, or net.ErrClosed after Close.
func (l *smbPipeListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case conn := <-l.connCh:
		return conn, nil
	}
}

func (l *smbPipeListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

// refillLoop recreates the pending instance whenever the previous one is
// consumed or fails to connect, backing off on transient CreateNamedPipe
// errors (e.g. resource exhaustion) instead of spinning.
func (l *smbPipeListener) refillLoop() {
	backoff := 50 * time.Millisecond
	for {
		select {
		case <-l.closed:
			return
		case <-l.refill:
		}
		for {
			if err := l.startConnector(); err == nil {
				backoff = 50 * time.Millisecond
				break
			}
			select {
			case <-l.closed:
				return
			case <-time.After(backoff):
			}
			if backoff < 2*time.Second {
				backoff *= 2
			}
		}
	}
}

// startConnector creates one pipe instance and launches a goroutine that waits
// for a client. On any terminal outcome it asks refillLoop for a replacement;
// the handle is closed only on failure, since a successfully wrapped pipeConn
// takes ownership of it.
func (l *smbPipeListener) startConnector() error {
	h, err := createPipeInstance(l.name)
	if err != nil {
		return err
	}
	go func() {
		// Ask for a replacement instance once this one is done.
		defer func() {
			select {
			case l.refill <- struct{}{}:
			default:
			}
		}()

		if err := connectPipe(l.closed, h); err != nil {
			windows.CloseHandle(h)
			if !errors.Is(err, net.ErrClosed) {
				logging.Debugf("smb listen %s: %v", l.name, err)
			}
			return
		}

		conn := newPipeConn(h, l.name, l.name)
		select {
		case l.connCh <- conn:
		case <-l.closed:
			conn.Close()
		}
	}()
	return nil
}

func createPipeInstance(fullName string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(fullName)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateNamedPipe(
		p,
		windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
		windows.PIPE_UNLIMITED_INSTANCES,
		smbPipeBufSize, smbPipeBufSize,
		0, nil,
	)
	if err != nil {
		return 0, fmt.Errorf("CreateNamedPipe %s: %w", fullName, err)
	}
	return h, nil
}

// connectPipe waits for a client to connect to an overlapped pipe instance.
// It polls in short intervals so listener shutdown (done closed) can abort it
// promptly. On any failure the pending ConnectNamedPipe is cancelled and its
// completion drained before the OVERLAPPED/event are released: closing a pipe
// with an outstanding overlapped connect lets the kernel write completion
// status into freed memory, which corrupts the process.
func connectPipe(done <-chan struct{}, h windows.Handle) error {
	ev, err := windows.CreateEvent(nil, 1, 0, nil) // manual-reset
	if err != nil {
		return fmt.Errorf("CreateEvent: %w", err)
	}
	defer windows.CloseHandle(ev)

	ov := &windows.Overlapped{HEvent: ev}
	connected := false
	defer func() {
		if connected {
			return
		}
		_ = windows.CancelIoEx(h, ov)
		var drained uint32
		_ = windows.GetOverlappedResult(h, ov, &drained, true)
	}()

	err = windows.ConnectNamedPipe(h, ov)
	switch {
	case err == nil:
		connected = true
		return nil
	case errors.Is(err, windows.ERROR_PIPE_CONNECTED):
		// A client connected between CreateNamedPipe and ConnectNamedPipe.
		connected = true
		return nil
	case !errors.Is(err, windows.ERROR_IO_PENDING):
		return fmt.Errorf("ConnectNamedPipe: %w", err)
	}

	for {
		status, werr := windows.WaitForSingleObject(ev, 200)
		if werr != nil {
			return fmt.Errorf("WaitForSingleObject: %w", werr)
		}
		switch status {
		case windows.WAIT_OBJECT_0:
			var doneBytes uint32
			if err := windows.GetOverlappedResult(h, ov, &doneBytes, false); err != nil {
				return fmt.Errorf("GetOverlappedResult: %w", err)
			}
			connected = true
			return nil
		case uint32(windows.WAIT_TIMEOUT):
			select {
			case <-done:
				return net.ErrClosed
			default:
			}
		default:
			return fmt.Errorf("unexpected wait status 0x%x", status)
		}
	}
}

// smbDialPipe connects to a peer's named pipe. Local hosts use \\.\pipe\ and
// remote hosts use \\host\pipe\, which the Windows SMB client carries over
// SMB using the current logon session.
func smbDialPipe(host string, port int, password, salt string) (net.Conn, error) {
	base := smbPipeBase(password, salt, port)
	full := `\\` + host + `\pipe\` + base
	if isSMBLocalHost(host) {
		full = `\\.\pipe\` + base
	}

	p, err := windows.UTF16PtrFromString(full)
	if err != nil {
		return nil, fmt.Errorf("smb dial %s: %w", full, err)
	}

	deadline := time.Now().Add(smbDialTimeout)
	for {
		h, err := windows.CreateFile(
			p,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED, 0,
		)
		if err == nil {
			return newPipeConn(h, full, full), nil
		}

		// ERROR_PIPE_BUSY: server has instances but all are connected.
		// ERROR_FILE_NOT_FOUND: peer has not created the pipe yet.
		if errors.Is(err, windows.ERROR_PIPE_BUSY) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("smb dial %s: %w", full, err)
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		return nil, fmt.Errorf("smb dial %s: %w", full, err)
	}
}

// isSMBLocalHost reports whether addr refers to this machine, in which case the
// local pipe namespace (\\.\pipe\) should be used instead of the SMB redirector.
func isSMBLocalHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" || host == "." || strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(ip) {
			return true
		}
	}
	return false
}
