//go:build linux && cgo
// +build linux,cgo

package coffloader

/*
#cgo linux CFLAGS: -fPIC -fvisibility=hidden
#cgo linux LDFLAGS: -ldl
#include <stdlib.h>
__attribute__((visibility("default")))
int bof_run(const unsigned char *obj_buf, size_t object_size, const char *func_name,
			const unsigned char *args_buf, int args_len, char **out_buf, char **err_buf);
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"unicode/utf16"
	"unsafe"
)

// RunLinuxCOFF executes an x86_64 ELF BOF payload on Linux using the Beacon arg format.
func RunLinuxCOFF(payload []byte, export string, args []CoffArg) (string, error) {
	if len(payload) == 0 {
		return "", fmt.Errorf("empty payload")
	}

	packedArgs, err := PackCoffArgs(args)
	if err != nil {
		return "", err
	}

	wire, err := packLinuxArgs(packedArgs)
	if err != nil {
		return "", err
	}

	if export == "" {
		export = "go"
	}

	cFunc := C.CString(export)
	defer C.free(unsafe.Pointer(cFunc))

	var argPtr *C.uchar
	var argLen C.int
	if len(wire) > 0 {
		argPtr = (*C.uchar)(unsafe.Pointer(&wire[0]))
		argLen = C.int(len(wire))
	}

	var outBuf *C.char
	var errBuf *C.char

	status := C.bof_run((*C.uchar)(unsafe.Pointer(&payload[0])), C.size_t(len(payload)), cFunc, argPtr, argLen, &outBuf, &errBuf)

	if errBuf != nil {
		defer C.free(unsafe.Pointer(errBuf))
	}
	if outBuf != nil {
		defer C.free(unsafe.Pointer(outBuf))
	}

	if status != 0 {
		if errBuf != nil {
			return "", fmt.Errorf("%s", C.GoString(errBuf))
		}
		return "", fmt.Errorf("linux BOF loader failed with status %d", int(status))
	}

	if outBuf == nil {
		return "", nil
	}

	return C.GoString(outBuf), nil
}

// packLinuxArgs mirrors lighthouse.PackArgs for the subset used by PackCoffArgs.
func packLinuxArgs(args []string) ([]byte, error) {
	if len(args) == 0 {
		return nil, nil
	}

	var body bytes.Buffer
	for _, arg := range args {
		if arg == "" {
			return nil, fmt.Errorf("empty arg")
		}

		switch arg[0] {
		case 'b':
			data, err := hex.DecodeString(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("pack binary: %w", err)
			}
			if err := binary.Write(&body, binary.LittleEndian, uint32(len(data))); err != nil {
				return nil, err
			}
			body.Write(data)
		case 'i':
			v, err := strconv.ParseInt(arg[1:], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("pack int: %w", err)
			}
			if err := binary.Write(&body, binary.LittleEndian, uint32(v)); err != nil {
				return nil, err
			}
		case 's':
			v, err := strconv.ParseInt(arg[1:], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("pack short: %w", err)
			}
			if err := binary.Write(&body, binary.LittleEndian, uint16(v)); err != nil {
				return nil, err
			}
		case 'z':
			u := utf16.Encode([]rune(arg[1:] + "\x00"))
			if err := binary.Write(&body, binary.LittleEndian, uint32(len(u))); err != nil {
				return nil, err
			}
			for _, r := range u {
				body.WriteByte(byte(r))
			}
		case 'Z':
			u := utf16.Encode([]rune(arg[1:]))
			buf := make([]byte, len(u)*2)
			for i, r := range u {
				buf[i*2] = byte(r)
				buf[i*2+1] = byte(r >> 8)
			}
			if err := binary.Write(&body, binary.LittleEndian, uint32(len(buf))); err != nil {
				return nil, err
			}
			body.Write(buf)
		default:
			return nil, fmt.Errorf("unknown arg prefix %q", arg[0])
		}
	}

	var final bytes.Buffer
	if err := binary.Write(&final, binary.LittleEndian, uint32(body.Len())); err != nil {
		return nil, err
	}
	final.Write(body.Bytes())
	return final.Bytes(), nil
}
