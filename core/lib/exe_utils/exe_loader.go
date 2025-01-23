//go:build cgo && linux
// +build cgo,linux

package exe_utils

import (
	"unsafe"
)

/*
#cgo amd64 CFLAGS: -DOS_LINUX -DGOARCH_amd64
#cgo 386 CFLAGS: -DOS_LINUX -DGOARCH_386
#cgo arm64 CFLAGS: -DOS_LINUX -DGOARCH_arm64
#cgo arm CFLAGS: -DOS_LINUX -DGOARCH_arm
#cgo ppc64 CFLAGS: -DOS_LINUX -DGOARCH_ppc64
#cgo riscv64 CFLAGS: -DOS_LINUX -DGOARCH_riscv64
#include <stdlib.h>
#include "elf_loader.h"
*/
import "C"

// InMemExeRun runs an ELF binary with the given arguments and environment variables, completely in memory.
func InMemExeRun(elf_data []byte, args []string, env []string) (output string, err error) {
	// Convert args and env to C strings
	c_args := make([]*C.char, len(args)+1)
	for i, arg := range args {
		c_args[i] = C.CString(arg)
	}
	c_args[len(args)] = nil
	c_env := make([]*C.char, len(env)+1)
	for i, e := range env {
		c_env[i] = C.CString(e)
	}
	c_env[len(env)] = nil

	// Call the C function
	ret := C.elf_fork_run(unsafe.Pointer(&elf_data[0]), &c_args[0], &c_env[0])
	// Free the C strings
	for _, arg := range c_args {
		C.free(unsafe.Pointer(arg))
	}
	for _, e := range c_env {
		C.free(unsafe.Pointer(e))
	}

	// save the output and return
	output = C.GoString(ret)
	C.free(unsafe.Pointer(ret))

	return output, nil
}
