//go:build amd64 && windows

package syscall

// UNICODE_STRING matches native NT structure layout on 64-bit (amd64) Windows.
type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	_             uint32 // Padding for 8-byte alignment on x64
	Buffer        *uint16
}

// PEB offsets for 64-bit Windows
const (
	pebLdrOffset           = 0x18
	ldrInMemoryOrderOffset = 0x20
	ldrEntryDllBaseOffset  = 0x20
	ldrEntryBaseNameOffset = 0x48
)

var syscallGadgetPatterns = [][]byte{
	{0x0F, 0x05, 0xC3}, // syscall; ret
}
