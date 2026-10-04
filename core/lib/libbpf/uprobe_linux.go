//go:build linux && !android && (386 || amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"fmt"
	"time"
)

// uprobeEventCommArgLayout documents the BPF program's `struct event` layout
// that UprobeEvent mirrors:
//
//	__u32 pid; __u32 uid; __s64 retval; char comm[16]; char arg[64];
const (
	uprobeCommLen   = 16
	uprobeArgLen    = 64
	uprobeEventSize = 4 + 4 + 8 + uprobeCommLen + uprobeArgLen
)

// uprobePollInterval is how often the events map is drained while a capture is
// running. Events are rare (one per authentication attempt), so a short poll
// only bounds worst-case latency without meaningful CPU cost.
const uprobePollInterval = 100 * time.Millisecond

// decodeUprobeEvent decodes a raw map value produced by the shipped BPF
// program. It validates the length so a map written by anything else cannot
// cause an out-of-range read.
func decodeUprobeEvent(raw []byte) (UprobeEvent, error) {
	if len(raw) < uprobeEventSize {
		return UprobeEvent{}, fmt.Errorf("libbpf: uprobe event is %d bytes, want %d", len(raw), uprobeEventSize)
	}
	return UprobeEvent{
		PID:    binary.LittleEndian.Uint32(raw[0:]),
		UID:    binary.LittleEndian.Uint32(raw[4:]),
		Retval: int64(binary.LittleEndian.Uint64(raw[8:])),
		Comm:   cStringBytes(raw[16 : 16+uprobeCommLen]),
		Arg:    cStringBytes(raw[16+uprobeCommLen : uprobeEventSize]),
	}, nil
}

// UprobeCapture describes one uprobe capture. The zero value is not valid:
// Image, Path and the map/program names must be set by the caller.
type UprobeCapture struct {
	Image         []byte
	ProgName      string
	EventsMapName string
	CfgMapName    string
	Path          string
	PID           int
	Offset        uint64
	ArgIndex      uint32

	// Timeout bounds a finite capture. It is ignored when UntilStopped is set.
	// A non-positive Timeout with UntilStopped unset performs a single drain.
	Timeout time.Duration
	// UntilStopped runs the capture until Stop is closed. It is what backs the
	// long-lived session API; the returned error is always nil when Stop fires.
	UntilStopped bool
	// Stop, when non-nil, ends the capture as soon as it is closed.
	Stop <-chan struct{}
	// OnAttached, when non-nil, is called exactly once after the uprobe is
	// attached. It lets a session launcher confirm the probe is live before
	// reporting success.
	OnAttached func()
	// OnEvent, when non-nil, is invoked for every event as it is drained. The
	// callback runs on the capture goroutine, so it must not block.
	OnEvent func(UprobeEvent)
}

// RunUprobeCapture loads image, attaches progName as a uprobe to path/offset,
// sets the argument register selector in cfgMapName, and drains eventsMapName
// according to opts. Every event is deleted from the map as it is read, so the
// capture never accumulates unbounded state.
//
// The libbpf mapping and every libbpf object live only for the duration of this
// call; only the kernel objects created during it persist, and they are torn
// down before RunUprobeCapture returns.
func RunUprobeCapture(opts UprobeCapture) error {
	return WithLibrary(func(lib *Library) error {
		obj, err := lib.OpenMem(opts.Image)
		if err != nil {
			return err
		}
		defer obj.Close()

		if err := obj.Load(); err != nil {
			return err
		}

		cfg, err := obj.FindMap(opts.CfgMapName)
		if err != nil {
			return fmt.Errorf("uprobe config map: %w", err)
		}
		cfgKey := make([]byte, 4) // index 0
		cfgVal := make([]byte, 4)
		binary.LittleEndian.PutUint32(cfgVal, opts.ArgIndex)
		if err := cfg.Update(cfgKey, cfgVal); err != nil {
			return fmt.Errorf("uprobe config: %w", err)
		}

		eventsMap, err := obj.FindMap(opts.EventsMapName)
		if err != nil {
			return fmt.Errorf("uprobe events map: %w", err)
		}
		prog, err := obj.FindProgram(opts.ProgName)
		if err != nil {
			return err
		}
		link, err := lib.AttachUprobe(prog, opts.PID, opts.Path, opts.Offset, false)
		if err != nil {
			return err
		}
		defer link.Destroy()

		if opts.OnAttached != nil {
			opts.OnAttached()
		}

		deadline := time.Now().Add(opts.Timeout)
		for {
			drainUprobeEvents(eventsMap, opts.OnEvent)
			if uprobeCaptureDone(opts, deadline) {
				return nil
			}
			time.Sleep(uprobePollInterval)
		}
	})
}

// uprobeCaptureDone reports whether the capture loop should stop after a drain.
func uprobeCaptureDone(opts UprobeCapture, deadline time.Time) bool {
	if opts.Stop != nil {
		select {
		case <-opts.Stop:
			return true
		default:
		}
	}
	if opts.UntilStopped {
		return false
	}
	return opts.Timeout <= 0 || !time.Now().Before(deadline)
}

// CaptureUprobe is the finite, collect-everything form of RunUprobeCapture: it
// attaches progName as a uprobe to path/offset, sets the argument register
// selector in cfgMapName, drains eventsMapName for timeout, and returns the
// captured events. This is the synchronous API used by the ebpf_uprobe_capture
// builtin; long-lived captures use RunUprobeCapture directly.
//
// pid selects the tracee: a negative value attaches to every process mapping
// the binary (covering future sessions too), while a non-negative value
// restricts the probe to that process. offset is a file offset; derive it with
// elfutil.FindCodePattern. argIndex selects which register is captured, using
// the order in ArgRegisters.
func CaptureUprobe(image []byte, progName, eventsMapName, cfgMapName, path string,
	pid int, offset uint64, argIndex uint32, timeout time.Duration,
) ([]UprobeEvent, error) {
	var events []UprobeEvent
	err := RunUprobeCapture(UprobeCapture{
		Image:         image,
		ProgName:      progName,
		EventsMapName: eventsMapName,
		CfgMapName:    cfgMapName,
		Path:          path,
		PID:           pid,
		Offset:        offset,
		ArgIndex:      argIndex,
		Timeout:       timeout,
		OnEvent: func(ev UprobeEvent) {
			events = append(events, ev)
		},
	})
	if err != nil {
		return nil, err
	}
	return events, nil
}

// drainUprobeEvents reads and removes every current entry of the events map,
// invoking emit for each decoded event. Keys are collected before any deletion
// so a hash map's iteration order is never disturbed mid-walk. Individual
// lookup/decode failures are skipped: one malformed entry must not stall the
// capture.
func drainUprobeEvents(m *Map, emit func(UprobeEvent)) {
	keys := make([][]byte, 0, 16)
	var prev []byte
	for i := 0; i < maxIDIter; i++ {
		next, err := m.NextKey(prev)
		if err != nil {
			break // empty map or end of iteration
		}
		keys = append(keys, next)
		prev = next
	}
	for _, key := range keys {
		raw, err := m.Lookup(key)
		if err != nil {
			continue
		}
		ev, err := decodeUprobeEvent(raw)
		if err != nil {
			continue
		}
		if emit != nil {
			emit(ev)
		}
		_ = m.Delete(key)
	}
}
