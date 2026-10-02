//go:build !linux || android || !(386 || amd64 || arm64)

package libbpf

import (
	"fmt"
)

// Library is a mapped libbpf.so.
type Library struct{}

// Object wraps a struct bpf_object *.
type Object struct{}

// Program wraps a struct bpf_program *.
type Program struct{}

// Link wraps a struct bpf_link *.
type Link struct{}

// ProgInfo summarises one kernel BPF program.
type ProgInfo struct {
	ID       uint32
	Type     uint32
	Name     string
	LoadTime uint64
}

// MapInfo summarises one kernel BPF map.
type MapInfo struct {
	ID         uint32
	Type       uint32
	Name       string
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
}

// LinkInfo summarises one kernel BPF link.
type LinkInfo struct {
	ID     uint32
	Type   uint32
	ProgID uint32
}

func unsupported() error {
	return fmt.Errorf("libbpf in-memory loader is unsupported on this platform")
}

// WithLibrary is unsupported off Linux.
func WithLibrary(func(*Library) error) error { return unsupported() }

// Load is unsupported off Linux.
func Load([]byte) (*Library, error) { return nil, unsupported() }

// Close is a no-op on unsupported platforms.
func (l *Library) Close() {}

// Version is unsupported off Linux.
func (l *Library) Version() (string, error) { return "", unsupported() }

// NumPossibleCPUs is unsupported off Linux.
func (l *Library) NumPossibleCPUs() (int, error) { return 0, unsupported() }

// OpenMem is unsupported off Linux.
func (l *Library) OpenMem([]byte) (*Object, error) { return nil, unsupported() }

// Load is unsupported off Linux.
func (o *Object) Load() error { return unsupported() }

// Close is a no-op on unsupported platforms.
func (o *Object) Close() {}

// FindProgram is unsupported off Linux.
func (o *Object) FindProgram(string) (*Program, error) { return nil, unsupported() }

// Attach is unsupported off Linux.
func (p *Program) Attach() (*Link, error) { return nil, unsupported() }

// Name is unsupported off Linux.
func (p *Program) Name() string { return "" }

// Destroy is a no-op on unsupported platforms.
func (l *Link) Destroy() {}

// ProgList is unsupported off Linux.
func (l *Library) ProgList() ([]ProgInfo, error) { return nil, unsupported() }

// LinkList is unsupported off Linux.
func (l *Library) LinkList() ([]LinkInfo, error) { return nil, unsupported() }

// MapList is unsupported off Linux.
func (l *Library) MapList() ([]MapInfo, error) { return nil, unsupported() }

// LinkDetach is unsupported off Linux.
func (l *Library) LinkDetach(uint32) error { return unsupported() }
