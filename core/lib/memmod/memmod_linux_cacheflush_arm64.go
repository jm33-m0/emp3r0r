//go:build !cgo && linux && !android && arm64

package memmod

// flushARM64InstructionCache performs the data-cache clean and instruction-cache
// invalidate sequence required after writing executable code. It reads the
// cache line sizes from CTR_EL0 so it stays correct on implementations with
// cache lines other than the common 64 bytes.
//
// This Go-assembly implementation is only used without cgo: cgo packages may
// not contain Go assembly, so the cgo build gets the same routine from
// memmod_linux_cacheflush_arm64_cgo.go instead.
//
//go:noescape
func flushARM64InstructionCache(start, end uintptr)

func flushLinuxInstructionCache(start, end uintptr) error {
	if start < end {
		flushARM64InstructionCache(start, end)
	}
	return nil
}
