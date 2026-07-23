//go:build windows
// +build windows

package netutil

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modiphlpapi       = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpNetTable = modiphlpapi.NewProc("GetIpNetTable")
)

type mibIpNetRow struct {
	Index       uint32
	PhysAddrLen uint32
	PhysAddr    [8]byte
	Addr        uint32
	Type        uint32
}

func IPNeigh() (table []string) {
	var size uint32
	// Call once to determine required buffer size
	ret, _, _ := procGetIpNetTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if size == 0 {
		return nil
	}

	buf := make([]byte, size)
	ret, _, _ = procGetIpNetTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if ret != 0 {
		return nil
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	if numEntries == 0 {
		return nil
	}

	offset := uintptr(4)
	for i := uint32(0); i < numEntries; i++ {
		row := (*mibIpNetRow)(unsafe.Pointer(&buf[offset]))
		offset += 24

		// Type 2 = MIB_IPNET_TYPE_INVALID (deleted/invalid)
		if row.Type == 2 || row.PhysAddrLen == 0 {
			continue
		}

		ip := fmt.Sprintf(
			"%d.%d.%d.%d",
			byte(row.Addr),
			byte(row.Addr>>8),
			byte(row.Addr>>16),
			byte(row.Addr>>24),
		)

		var mac string
		if row.PhysAddrLen <= 8 {
			for j := uint32(0); j < row.PhysAddrLen; j++ {
				if j > 0 {
					mac += ":"
				}
				mac += fmt.Sprintf("%02x", row.PhysAddr[j])
			}
		}

		if mac != "" {
			table = append(table, fmt.Sprintf("%s (%s), ", ip, mac))
		}
	}

	return table
}

func IPr() (routes []string) {
	return routes
}
