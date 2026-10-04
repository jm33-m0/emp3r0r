//go:build !linux || android || !(386 || amd64 || arm64)

package libbpf

import (
	"fmt"
	"time"
)

// Library is a mapped libbpf.so.
type Library struct{}

// Object wraps a struct bpf_object *.
type Object struct{}

// Program wraps a struct bpf_program *.
type Program struct{}

// Map wraps a struct bpf_map *.
type Map struct{}

// Link wraps a struct bpf_link *.
type Link struct{}

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

// FindMap is unsupported off Linux.
func (o *Object) FindMap(string) (*Map, error) { return nil, unsupported() }

// AttachUprobe is unsupported off Linux.
func (l *Library) AttachUprobe(*Program, int, string, uint64, bool) (*Link, error) {
	return nil, unsupported()
}

// FD is unsupported off Linux.
func (m *Map) FD() (int, error) { return -1, unsupported() }

// KeySize is unsupported off Linux.
func (m *Map) KeySize() (uint32, error) { return 0, unsupported() }

// ValueSize is unsupported off Linux.
func (m *Map) ValueSize() (uint32, error) { return 0, unsupported() }

// Update is unsupported off Linux.
func (m *Map) Update([]byte, []byte) error { return unsupported() }

// Lookup is unsupported off Linux.
func (m *Map) Lookup([]byte) ([]byte, error) { return nil, unsupported() }

// Delete is unsupported off Linux.
func (m *Map) Delete([]byte) error { return unsupported() }

// NextKey is unsupported off Linux.
func (m *Map) NextKey([]byte) ([]byte, error) { return nil, unsupported() }

// FD is unsupported off Linux.
func (l *Link) FD() (int, error) { return -1, unsupported() }

// UprobeCapture describes one uprobe capture (unsupported off Linux).
type UprobeCapture struct {
	Image         []byte
	ProgName      string
	EventsMapName string
	CfgMapName    string
	Path          string
	PID           int
	Offset        uint64
	ArgIndex      uint32
	Timeout       time.Duration
	UntilStopped  bool
	Stop          <-chan struct{}
	OnAttached    func()
	OnEvent       func(UprobeEvent)
}

// RunUprobeCapture is unsupported off Linux.
func RunUprobeCapture(UprobeCapture) error { return unsupported() }

// CaptureUprobe is unsupported off Linux.
func CaptureUprobe([]byte, string, string, string, string, int, uint64, uint32, time.Duration) ([]UprobeEvent, error) {
	return nil, unsupported()
}

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

// MapDeleteAll is unsupported off Linux.
func (l *Library) MapDeleteAll(uint32) (int, error) { return 0, unsupported() }
