package network

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// Shared server variables and globals
var (
	EmpTLSServer       *http.Server
	EmpTLSListener     net.Listener
	EmpTLSServerCtx    context.Context
	EmpTLSServerCancel context.CancelFunc
	EmpKCPCtx          context.Context
	EmpKCPCancel       context.CancelFunc

	// Shared stream handlers and maps
	FTPStreams sync.Map
)

// StopEmpTLSServer stops whichever C2 TLS endpoint is currently active.
// It supports both HTTP-fronted and raw TLS listener modes.
func StopEmpTLSServer() {
	if EmpTLSServer != nil {
		_ = EmpTLSServer.Shutdown(EmpTLSServerCtx)
		EmpTLSServer = nil
	}
	if EmpTLSServerCancel != nil {
		EmpTLSServerCancel()
		EmpTLSServerCancel = nil
	}
	if EmpTLSListener != nil {
		_ = EmpTLSListener.Close()
		EmpTLSListener = nil
	}
	EmpTLSServerCtx = nil
}

// StreamHandler allows the HTTP handler to use CBOR-encapsulated streams.
type StreamHandler struct {
	Secure          io.ReadWriter // The SecureConn (PSK or Session Key)
	Token           string        // token string for identification
	StreamID        string        // stream identifier bound at registration
	Capability      string        // operator capability bound at registration
	OperatorSession string        // stream owner operator session id
	ExpectedSize    int64         // expected final file size for file transfers
	Checksum        string        // expected checksum for file transfers
	Ctx             context.Context
	Cancel          context.CancelFunc
	IsClosed        bool
}

// Read implements io.Reader by reading from the internal buffer.
// This buffer is filled by the dispatcher when it receives a MsgTunData frame for this handler.
func (sh *StreamHandler) Read(p []byte) (n int, err error) {
	// New C2 protocol mode: raw stream handler (e.g. FTP upload over CBOR-routed
	// SecureConn) reads directly from the secure stream if available.
	if sh.Secure != nil {
		r, ok := sh.Secure.(io.Reader)
		if !ok {
			return 0, fmt.Errorf("StreamHandler: secure stream is not readable")
		}
		return r.Read(p)
	}

	return 0, io.EOF
}

// Write implements io.Writer by wrapping the data in a MsgTunData CBOR envelope
// and sending it over the SecureConn.
func (sh *StreamHandler) Write(p []byte) (n int, err error) {
	if sh.Secure == nil {
		return 0, fmt.Errorf("StreamHandler: No secure connection")
	}
	msg := def.MsgTunData{
		Response: p,
		Tag:      sh.Token, // Use token as tag for routing back to agent
	}
	err = cbor.NewEncoder(sh.Secure).Encode(msg)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (sh *StreamHandler) Close() error {
	sh.IsClosed = true
	sh.Cancel()
	return nil
}
