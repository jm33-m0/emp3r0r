package coffloader

import (
	"unicode/utf16"
	"unsafe"
)

func CopyMemory(dst, src uintptr, length uint32) {
	copy((*[1 << 30]byte)(unsafe.Pointer(dst))[:length], (*[1 << 30]byte)(unsafe.Pointer(src))[:length])
}

func ReadBytesFromPtr(src uintptr, length uint32) (out []byte) {
	if src == 0 || length == 0 {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			out = nil
		}
	}()
	out = make([]byte, length)
	CopyMemory(uintptr(unsafe.Pointer(&out[0])), src, length)
	return out
}

func ReadUIntFromPtr(src uintptr) uint32 {
	return *(*uint32)(unsafe.Pointer(src))
}

func ReadShortFromPtr(src uintptr) uint16 {
	return *(*uint16)(unsafe.Pointer(src))
}

func ReadCStringFromPtr(src uintptr) (str string) {
	if src == 0 {
		return ""
	}
	defer func() {
		if r := recover(); r != nil {
			// Catch memory protection fault on invalid/freed pointers
		}
	}()
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
