//go:build !cgo && linux && !android && (386 || amd64 || arm64)

package memmod

// callExportFunction invokes a native function through the architecture's
// assembly trampoline (cCall0..cCall5 are defined in memmod_elf_*.s). Using
// the thin trampoline instead of a reflection-based syscall wrapper keeps the
// call ABI exact and avoids pulling in an extra dependency.
//
//go:uintptrescapes
func callExportFunction(fn uintptr, args ...uintptr) uintptr {
	switch len(args) {
	case 0:
		return cCall0(fn)
	case 1:
		return cCall1(fn, args[0])
	case 2:
		return cCall2(fn, args[0], args[1])
	case 3:
		return cCall3(fn, args[0], args[1], args[2])
	case 4:
		return cCall4(fn, args[0], args[1], args[2], args[3])
	case 5:
		return cCall5(fn, args[0], args[1], args[2], args[3], args[4])
	default:
		panic("validated ELF export argument count is out of range")
	}
}
