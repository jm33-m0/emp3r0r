package coffloader

import (
	"unicode/utf16"
	"unsafe"
)

func CopyMemory(dst, src uintptr, length uint32) {
	copy((*[1 << 30]byte)(unsafe.Pointer(dst))[:length], (*[1 << 30]byte)(unsafe.Pointer(src))[:length])
}

func ReadBytesFromPtr(src uintptr, length uint32) []byte {
	out := make([]byte, length)
	CopyMemory(uintptr(unsafe.Pointer(&out[0])), src, length)
	return out
}

func ReadUIntFromPtr(src uintptr) uint32 {
	return *(*uint32)(unsafe.Pointer(src))
}

func ReadShortFromPtr(src uintptr) uint16 {
	return *(*uint16)(unsafe.Pointer(src))
}

func ReadCStringFromPtr(src uintptr) string {
	if src == 0 {
		return ""
	}
	str := ""
	offset := 0
	for {
		c := *(*byte)(unsafe.Pointer(src + uintptr(offset)))
		if c == 0 {
			break
		}
		str += string(c)
		offset++
	}
	return str
}

func ReadWStringFromPtr(src uintptr) string {
	if src == 0 {
		return ""
	}
	var codeUnits []uint16
	offset := uintptr(0)
	for {
		c := *(*uint16)(unsafe.Pointer(src + offset))
		if c == 0 {
			break
		}
		codeUnits = append(codeUnits, c)
		offset += 2
	}
	return string(utf16.Decode(codeUnits))
}
