//go:build 386 && windows

package syscall

// UNICODE_STRING matches native NT structure layout on 32-bit (386) Windows.
type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

// PEB offsets for 32-bit Windows
const (
	pebLdrOffset           = 0x0C
	ldrInMemoryOrderOffset = 0x14
	ldrEntryDllBaseOffset  = 0x10
	ldrEntryBaseNameOffset = 0x24
)

var syscallGadgetPatterns = [][]byte{
	{0xFF, 0xD2, 0xC2}, // call edx; ret N (WOW64 syscall transition)
	{0xFF, 0xD2, 0xC3}, // call edx; ret
	{0x0F, 0x34, 0xC3}, // sysenter; ret
	{0x0F, 0x34, 0xC2}, // sysenter; ret N
}
