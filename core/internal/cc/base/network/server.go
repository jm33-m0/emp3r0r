package network

import (
	"context"
	"net/http"
	"sync"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
)

// Shared server variables and globals
var (
	EmpTLSServer       *http.Server
	EmpTLSServerCtx    context.Context
	EmpTLSServerCancel context.CancelFunc

	// Shared stream handlers and maps
	RShellStream  = &StreamHandler{H2x: nil, BufSize: def.RShellBufSize, Buf: make(chan []byte)}
	ProxyStream   = &StreamHandler{H2x: nil, BufSize: def.ProxyBufSize, Buf: make(chan []byte)}
	FTPStreams    = make(map[string]*StreamHandler)
	FTPMutex      = &sync.Mutex{}
	RShellStreams = make(map[string]*StreamHandler)
	RShellMutex   = &sync.Mutex{}
	PortFwds      = make(map[string]*PortFwdSession)
	PortFwdsMutex = &sync.Mutex{}
)

// StreamHandler allows the HTTP handler to use H2Conn.
type StreamHandler struct {
	H2x     *def.H2Conn // H2Conn with context
	Buf     chan []byte // buffer for receiving data
	Token   string      // token string for authentication
	BufSize int         // buffer size (e.g., for reverse shell)
}
