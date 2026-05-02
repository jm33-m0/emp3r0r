package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"
)

// StreamTransport defines a protocol-agnostic byte-stream wrapper.
// Higher protocol layers should only rely on Read/Write/Close semantics.
type StreamTransport interface {
	net.Conn
	RemoteAddrString() string
}

// C2Transport is kept as a compatibility alias for existing call sites.
type C2Transport = StreamTransport

// C2ChannelWrapper is the pluggable outer wrapper for C2 byte streams.
// It must not contain trust or routing logic; those stay in CBOR payload handlers.
type C2ChannelWrapper interface {
	Dial(ctx context.Context, client *http.Client, url string) (io.ReadWriteCloser, *http.Response, error)
	Accept(w http.ResponseWriter, req *http.Request) (io.ReadWriteCloser, error)
}

// C2ChannelDescriptor carries metadata and implementation for a channel wrapper.
type C2ChannelDescriptor struct {
	Name        string
	Description string
	Wrapper     C2ChannelWrapper
}

// C2Channels stores registered channel wrappers.
var C2Channels sync.Map

// RegisterC2Channel registers a named outer channel wrapper.
func RegisterC2Channel(name, desc string, wrapper C2ChannelWrapper) {
	C2Channels.Store(name, &C2ChannelDescriptor{
		Name:        name,
		Description: desc,
		Wrapper:     wrapper,
	})
}

// GetC2ChannelWrapper returns the wrapper implementation for a channel mode.
func GetC2ChannelWrapper(mode string) (C2ChannelWrapper, error) {
	val, ok := C2Channels.Load(mode)
	if !ok {
		return nil, fmt.Errorf("unknown c2 channel mode %q", mode)
	}
	desc, ok := val.(*C2ChannelDescriptor)
	if !ok || desc == nil || desc.Wrapper == nil {
		return nil, fmt.Errorf("invalid c2 channel descriptor for mode %q", mode)
	}
	return desc.Wrapper, nil
}

// AllC2ChannelModes returns a sorted list of registered C2 channel modes.
func AllC2ChannelModes() []string {
	var names []string
	C2Channels.Range(func(key, value any) bool {
		name, ok := key.(string)
		if ok {
			names = append(names, name)
		}
		return true
	})
	sort.Strings(names)
	return names
}

func AllC2ChannelModesDetailed() []string {
	descriptions := []string{}
	// Get C2 channel descriptions
	C2Channels.Range(func(key, value any) bool {
		descriptor := value.(C2ChannelDescriptor)
		description := fmt.Sprintf("%s: %s", descriptor.Name, descriptor.Description)
		descriptions = append(descriptions, description)
		return true
	})
	sort.Strings(descriptions)
	return descriptions
}

// GenericStreamTransport adapts a raw ReadWriteCloser to the StreamTransport interface.
// It intentionally exposes only byte-stream semantics to higher protocol layers.
type GenericStreamTransport struct {
	Conn io.ReadWriteCloser
	addr string
}

// NewStreamTransport creates a protocol-agnostic stream adapter for C2 traffic.
func NewStreamTransport(conn io.ReadWriteCloser, remoteAddr string) C2Transport {
	return &GenericStreamTransport{Conn: conn, addr: remoteAddr}
}

func (t *GenericStreamTransport) Read(p []byte) (int, error)  { return t.Conn.Read(p) }
func (t *GenericStreamTransport) Write(p []byte) (int, error) { return t.Conn.Write(p) }
func (t *GenericStreamTransport) Close() error                { return t.Conn.Close() }
func (t *GenericStreamTransport) RemoteAddrString() string    { return t.addr }

// net.Conn implementation stubs
func (t *GenericStreamTransport) LocalAddr() net.Addr              { return nil }
func (t *GenericStreamTransport) RemoteAddr() net.Addr             { return nil }
func (t *GenericStreamTransport) SetDeadline(time.Time) error      { return nil }
func (t *GenericStreamTransport) SetReadDeadline(time.Time) error  { return nil }
func (t *GenericStreamTransport) SetWriteDeadline(time.Time) error { return nil }
