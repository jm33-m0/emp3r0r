// Package agenttransport defines the agent-side transport boundary.
//
// A transport is only responsible for producing a reliable, ordered,
// bidirectional byte stream to the C2. Authentication, framing, encryption,
// routing, and reconnect policy live above this package. Custom transports
// register a Dialer during init; the agent resolves one by the configured
// channel mode before every connection attempt.
package agenttransport

import (
	"context"
	"fmt"
	"io"
	"sort"
	"sync"
)

// Target is the transport-neutral endpoint description passed to a Dialer.
// Address is opaque to the core: HTTP dialers may parse it as a URL, while a
// DNS, SMB, or application-protocol dialer may interpret it as a zone, pipe
// name, drive folder, or chat identifier.
type Target struct {
	Address string
	Proxy   string
	Options map[string]string
}

// Dialer opens one transport pipe. The returned stream is wrapped in
// transport.SecureConn by the caller, so a Dialer must never parse or alter
// the bytes it carries.
type Dialer interface {
	Name() string
	Dial(ctx context.Context, target Target) (io.ReadWriteCloser, error)
}

var dialers sync.Map // map[string]Dialer

// Register adds a dialer to the process-wide registry. Registration happens
// during package init; a duplicate name is a programming error.
func Register(d Dialer) {
	if d == nil {
		panic("agenttransport: nil dialer")
	}
	name := d.Name()
	if name == "" {
		panic("agenttransport: dialer has an empty name")
	}
	if _, loaded := dialers.LoadOrStore(name, d); loaded {
		panic(fmt.Sprintf("agenttransport: dialer %q is already registered", name))
	}
}

// Get resolves a registered dialer by name.
func Get(name string) (Dialer, error) {
	if name == "" {
		return nil, fmt.Errorf("agenttransport: empty transport name")
	}
	val, ok := dialers.Load(name)
	if !ok {
		return nil, fmt.Errorf("agenttransport: unknown transport %q (available: %v)", name, Names())
	}
	d, ok := val.(Dialer)
	if !ok || d == nil {
		return nil, fmt.Errorf("agenttransport: invalid dialer for %q", name)
	}
	return d, nil
}

// Names returns the registered transport names in sorted order.
func Names() []string {
	names := make([]string, 0)
	dialers.Range(func(key, _ any) bool {
		if name, ok := key.(string); ok {
			names = append(names, name)
		}
		return true
	})
	sort.Strings(names)
	return names
}
