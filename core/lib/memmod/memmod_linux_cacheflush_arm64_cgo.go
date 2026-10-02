//go:build cgo && linux && !android && arm64

package memmod

/*
#include <stdint.h>

// memmod_flush_instruction_cache cleans the data cache and invalidates the
// instruction cache over [start, end). The compiler lowers the builtin to the
// architecture's dc cvau / dsb ish / ic ivau / dsb ish / isb sequence, which
// keeps the cgo build correct without duplicating the hand-written encoding
// used in the non-cgo assembly implementation.
static void memmod_flush_instruction_cache(uintptr_t start, uintptr_t end) {
	__builtin___clear_cache((char *)start, (char *)end);
}
*/
import "C"

func flushLinuxInstructionCache(start, end uintptr) error {
	if start < end {
		C.memmod_flush_instruction_cache(C.uintptr_t(start), C.uintptr_t(end))
	}
	return nil
}
