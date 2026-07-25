package script

import (
	"fmt"
	"runtime"
	"unsafe"

	"go.starlark.net/starlark"
)

// readMemoryBytes reads raw memory bytes safely from address across platforms
func readMemoryBytes(addr uintptr, size int) ([]byte, error) {
	if addr == 0 || addr < 4096 {
		return nil, fmt.Errorf("invalid memory address 0x%x", addr)
	}
	if size <= 0 {
		return nil, nil
	}

	if runtime.GOOS == "windows" {
		return readWinMem(addr, size)
	}
	return readLinuxMem(addr, size)
}

// writeMemoryBytes writes raw bytes to target memory address safely
func writeMemoryBytes(addr uintptr, data []byte) error {
	if addr == 0 || addr < 4096 {
		return fmt.Errorf("invalid memory address 0x%x", addr)
	}
	if len(data) == 0 {
		return nil
	}

	defer func() {
		if r := recover(); r != nil {
			_ = r
		}
	}()

	mem := *(*[]byte)(unsafe.Pointer(&struct {
		addr uintptr
		len  int
		cap  int
	}{addr, len(data), len(data)}))
	copy(mem, data)
	return nil
}

func starlarkReadUint8(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var addr uint64
	offset := 0
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &addr, "offset?", &offset); err != nil {
		return starlark.None, err
	}
	b, err := readMemoryBytes(uintptr(addr)+uintptr(offset), 1)
	if err != nil || len(b) < 1 {
		return starlark.MakeInt(0), nil
	}
	return starlark.MakeInt(int(b[0])), nil
}

func starlarkReadUint16(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var addr uint64
	offset := 0
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &addr, "offset?", &offset); err != nil {
		return starlark.None, err
	}
	b, err := readMemoryBytes(uintptr(addr)+uintptr(offset), 2)
	if err != nil || len(b) < 2 {
		return starlark.MakeInt(0), nil
	}
	val := uint16(b[0]) | (uint16(b[1]) << 8)
	return starlark.MakeInt(int(val)), nil
}

func starlarkReadUint32(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var addr uint64
	offset := 0
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &addr, "offset?", &offset); err != nil {
		return starlark.None, err
	}
	b, err := readMemoryBytes(uintptr(addr)+uintptr(offset), 4)
	if err != nil || len(b) < 4 {
		return starlark.MakeUint64(0), nil
	}
	val := uint32(b[0]) | (uint32(b[1]) << 8) | (uint32(b[2]) << 16) | (uint32(b[3]) << 24)
	return starlark.MakeUint64(uint64(val)), nil
}

func starlarkReadUint64(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var addr uint64
	offset := 0
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &addr, "offset?", &offset); err != nil {
		return starlark.None, err
	}
	b, err := readMemoryBytes(uintptr(addr)+uintptr(offset), 8)
	if err != nil || len(b) < 8 {
		return starlark.MakeUint64(0), nil
	}
	val := uint64(b[0]) | (uint64(b[1]) << 8) | (uint64(b[2]) << 16) | (uint64(b[3]) << 24) |
		(uint64(b[4]) << 32) | (uint64(b[5]) << 40) | (uint64(b[6]) << 48) | (uint64(b[7]) << 56)
	return starlark.MakeUint64(val), nil
}

func starlarkReadInt32(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var addr uint64
	offset := 0
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &addr, "offset?", &offset); err != nil {
		return starlark.None, err
	}
	b, err := readMemoryBytes(uintptr(addr)+uintptr(offset), 4)
	if err != nil || len(b) < 4 {
		return starlark.MakeInt(0), nil
	}
	val := int32(uint32(b[0]) | (uint32(b[1]) << 8) | (uint32(b[2]) << 16) | (uint32(b[3]) << 24))
	return starlark.MakeInt(int(val)), nil
}

func starlarkReadWString(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ptr uint64
	maxLen := 256
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &ptr, "max_len?", &maxLen); err != nil {
		return starlark.None, err
	}
	if ptr == 0 {
		return starlark.String(""), nil
	}
	b, err := readMemoryBytes(uintptr(ptr), maxLen*2)
	if err != nil || len(b) < 2 {
		return starlark.String(""), nil
	}
	var runes []rune
	for i := 0; i+1 < len(b); i += 2 {
		u := uint16(b[i]) | (uint16(b[i+1]) << 8)
		if u == 0 {
			break
		}
		runes = append(runes, rune(u))
	}
	return starlark.String(string(runes)), nil
}

func starlarkReadCString(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ptr uint64
	maxLen := 256
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &ptr, "max_len?", &maxLen); err != nil {
		return starlark.None, err
	}
	if ptr == 0 {
		return starlark.String(""), nil
	}
	b, err := readMemoryBytes(uintptr(ptr), maxLen)
	if err != nil || len(b) == 0 {
		return starlark.String(""), nil
	}
	for i, ch := range b {
		if ch == 0 {
			return starlark.String(string(b[:i])), nil
		}
	}
	return starlark.String(string(b)), nil
}

func starlarkWriteUint8(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var addr uint64
	var offset, val int
	if len(args) == 2 {
		if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &addr, "val", &val); err != nil {
			return starlark.None, err
		}
		offset = 0
	} else {
		if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &addr, "offset", &offset, "val", &val); err != nil {
			return starlark.None, err
		}
	}
	_ = writeMemoryBytes(uintptr(addr)+uintptr(offset), []byte{byte(val & 0xFF)})
	return starlark.None, nil
}

func starlarkWriteUint16(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var addr uint64
	var offset, val int
	if len(args) == 2 {
		if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &addr, "val", &val); err != nil {
			return starlark.None, err
		}
		offset = 0
	} else {
		if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &addr, "offset", &offset, "val", &val); err != nil {
			return starlark.None, err
		}
	}
	v := uint16(val)
	b := []byte{byte(v & 0xFF), byte((v >> 8) & 0xFF)}
	_ = writeMemoryBytes(uintptr(addr)+uintptr(offset), b)
	return starlark.None, nil
}

func starlarkWriteUint32(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var addr uint64
	var offset int
	var valVal starlark.Value
	if len(args) == 2 {
		if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &addr, "val", &valVal); err != nil {
			return starlark.None, err
		}
		offset = 0
	} else {
		if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &addr, "offset", &offset, "val", &valVal); err != nil {
			return starlark.None, err
		}
	}
	var v uint32
	if starInt, ok := valVal.(starlark.Int); ok {
		if u, ok := starInt.Uint64(); ok {
			v = uint32(u)
		} else if i, ok := starInt.Int64(); ok {
			v = uint32(i)
		}
	}
	b := []byte{byte(v & 0xFF), byte((v >> 8) & 0xFF), byte((v >> 16) & 0xFF), byte((v >> 24) & 0xFF)}
	_ = writeMemoryBytes(uintptr(addr)+uintptr(offset), b)
	return starlark.None, nil
}

func starlarkWriteUint64(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var addr uint64
	var offset int
	var valVal starlark.Value
	if len(args) == 2 {
		if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &addr, "val", &valVal); err != nil {
			return starlark.None, err
		}
		offset = 0
	} else {
		if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "address", &addr, "offset", &offset, "val", &valVal); err != nil {
			return starlark.None, err
		}
	}
	var v uint64
	if starInt, ok := valVal.(starlark.Int); ok {
		if u, ok := starInt.Uint64(); ok {
			v = u
		} else if i, ok := starInt.Int64(); ok {
			v = uint64(i)
		}
	}
	b := []byte{
		byte(v & 0xFF), byte((v >> 8) & 0xFF), byte((v >> 16) & 0xFF), byte((v >> 24) & 0xFF),
		byte((v >> 32) & 0xFF), byte((v >> 40) & 0xFF), byte((v >> 48) & 0xFF), byte((v >> 56) & 0xFF),
	}
	_ = writeMemoryBytes(uintptr(addr)+uintptr(offset), b)
	return starlark.None, nil
}

func starlarkUTF16Ptr(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "s", &s); err != nil {
		return starlark.None, err
	}
	if s == "" {
		return starlark.MakeUint64(0), nil
	}
	runes := []rune(s)
	buf := make([]byte, (len(runes)+1)*2)
	for i, r := range runes {
		u := uint16(r)
		buf[i*2] = byte(u & 0xFF)
		buf[i*2+1] = byte((u >> 8) & 0xFF)
	}

	var allocFn starlark.Value
	if runtime.GOOS == "windows" {
		allocFn = getAPIs()["win_alloc"]
	} else {
		allocFn = getAPIs()["sys_alloc"]
	}
	if allocCallable, ok := allocFn.(starlark.Callable); ok {
		res, err := starlark.Call(thread, allocCallable, starlark.Tuple{starlark.MakeInt(len(buf))}, nil)
		if err != nil {
			return starlark.None, err
		}
		if ptrInt, ok := res.(starlark.Int); ok {
			if u, ok := ptrInt.Uint64(); ok {
				_ = writeMemoryBytes(uintptr(u), buf)
				return res, nil
			}
		}
	}
	return starlark.MakeUint64(0), nil
}

func starlarkCStringPtr(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "s", &s); err != nil {
		return starlark.None, err
	}
	if s == "" {
		return starlark.MakeUint64(0), nil
	}
	buf := append([]byte(s), 0)
	var allocFn starlark.Value
	if runtime.GOOS == "windows" {
		allocFn = getAPIs()["win_alloc"]
	} else {
		allocFn = getAPIs()["sys_alloc"]
	}
	if allocCallable, ok := allocFn.(starlark.Callable); ok {
		res, err := starlark.Call(thread, allocCallable, starlark.Tuple{starlark.MakeInt(len(buf))}, nil)
		if err != nil {
			return starlark.None, err
		}
		if ptrInt, ok := res.(starlark.Int); ok {
			if u, ok := ptrInt.Uint64(); ok {
				_ = writeMemoryBytes(uintptr(u), buf)
				return res, nil
			}
		}
	}
	return starlark.MakeUint64(0), nil
}
