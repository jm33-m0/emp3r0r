package libbpf

// ProgInfo summarises one kernel BPF program.
type ProgInfo struct {
	ID       uint32
	Type     uint32
	Name     string
	LoadTime uint64
	JitedLen uint32
	NrMaps   uint32
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

// LinkInfo summarises one kernel BPF link. ProgType is the type of the program
// the link attaches; it is 0 when the program could not be inspected.
type LinkInfo struct {
	ID       uint32
	Type     uint32
	ProgID   uint32
	ProgType uint32
}

// Stable BPF UAPI enum values. They are part of the kernel ABI and are kept in
// Go so callers do not need kernel headers to classify objects. Values match
// include/uapi/linux/bpf.h.
const (
	ProgTypeKprobe                uint32 = 2
	ProgTypeTracepoint            uint32 = 5
	ProgTypePerfEvent             uint32 = 7
	ProgTypeRawTracepoint         uint32 = 17
	ProgTypeRawTracepointWritable uint32 = 24
	ProgTypeTracing               uint32 = 26
	ProgTypeLSM                   uint32 = 29
)

const (
	MapTypeHash           uint32 = 1
	MapTypeArray          uint32 = 2
	MapTypePerfEventArray uint32 = 4
	MapTypeLruHash        uint32 = 9
	MapTypeRingbuf        uint32 = 27
)

// MonitoringProgType reports whether t is a tracing/LSM program type that an
// EDR uses to observe system activity. It mirrors Furtex's is_monitoring_prog.
func MonitoringProgType(t uint32) bool {
	switch t {
	case ProgTypeKprobe, ProgTypeTracepoint, ProgTypePerfEvent,
		ProgTypeRawTracepoint, ProgTypeRawTracepointWritable,
		ProgTypeTracing, ProgTypeLSM:
		return true
	}
	return false
}
