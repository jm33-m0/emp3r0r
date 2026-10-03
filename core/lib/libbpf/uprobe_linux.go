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

// CaptureUprobe loads image, attaches progName as a uprobe to path/offset, sets
// the argument register selector in cfgMapName, and drains eventsMapName until
// timeout elapses. Every event is deleted from the map as it is read, so the
// returned slice has no duplicates and a long-lived probe does not accumulate
// unbounded state.
//
// pid selects the tracee: a negative value attaches to every process mapping
// the binary (covering future sessions too), while a non-negative value
// restricts the probe to that process. offset is a file offset; derive it with
// elfutil.FindCodePattern. argIndex selects which register is captured, using
// the order in ArgRegisters.
//
// The libbpf mapping and every libbpf object live only for the duration of this
// call; only the kernel objects created during it persist, and they are torn
// down before CaptureUprobe returns.
func CaptureUprobe(image []byte, progName, eventsMapName, cfgMapName, path string,
	pid int, offset uint64, argIndex uint32, timeout time.Duration,
) ([]UprobeEvent, error) {
	var events []UprobeEvent
	err := WithLibrary(func(lib *Library) error {
		obj, err := lib.OpenMem(image)
		if err != nil {
			return err
		}
		defer obj.Close()

		if err := obj.Load(); err != nil {
			return err
		}

		cfg, err := obj.FindMap(cfgMapName)
		if err != nil {
			return fmt.Errorf("uprobe config map: %w", err)
		}
		cfgKey := make([]byte, 4) // index 0
		cfgVal := make([]byte, 4)
		binary.LittleEndian.PutUint32(cfgVal, argIndex)
		if err := cfg.Update(cfgKey, cfgVal); err != nil {
			return fmt.Errorf("uprobe config: %w", err)
		}

		eventsMap, err := obj.FindMap(eventsMapName)
		if err != nil {
			return fmt.Errorf("uprobe events map: %w", err)
		}
		prog, err := obj.FindProgram(progName)
		if err != nil {
			return err
		}
		link, err := lib.AttachUprobe(prog, pid, path, offset, false)
		if err != nil {
			return err
		}
		defer link.Destroy()

		deadline := time.Now().Add(timeout)
		for {
			drainUprobeEvents(eventsMap, &events)
			if timeout <= 0 || !time.Now().Before(deadline) {
				return nil
			}
			time.Sleep(uprobePollInterval)
		}
	})
	if err != nil {
		return nil, err
	}
	return events, nil
}

// drainUprobeEvents reads and removes every current entry of the events map.
// Keys are collected before any deletion so a hash map's iteration order is
// never disturbed mid-walk. Individual lookup/decode failures are skipped: one
// malformed entry must not stall the capture.
func drainUprobeEvents(m *Map, out *[]UprobeEvent) {
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
		*out = append(*out, ev)
		_ = m.Delete(key)
	}
}
