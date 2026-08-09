//go:build arm64 && windows

package syscall

// UNICODE_STRING matches native NT structure layout on 64-bit (arm64) Windows.
type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	_             uint32 // Padding for 8-byte alignment on 64-bit
	Buffer        *uint16
}

// PEB offsets for 64-bit Windows
const (
	pebLdrOffset           = 0x18
	ldrInMemoryOrderOffset = 0x20
	ldrEntryDllBaseOffset  = 0x20
	ldrEntryBaseNameOffset = 0x48
)

var syscallGadgetPatterns = [][]byte{}
