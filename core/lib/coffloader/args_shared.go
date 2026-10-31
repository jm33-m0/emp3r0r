package coffloader

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
)

// CoffArg represents a single BOF/COFF argument with its wire type.
type CoffArg struct {
	WireType string
	Value    any
}

// PackCoffArgs converts CoffArg values to the COFFLoader BOF wire format.
func PackCoffArgs(args []CoffArg) ([]string, error) {
	packed := make([]string, 0, len(args))
	for _, arg := range args {
		normalized, err := normalizeCoffValue(arg)
		if err != nil {
			return nil, err
		}
		packed = append(packed, normalized)
	}
	return packed, nil
}

func normalizeCoffValue(arg CoffArg) (string, error) {
	val := arg.Value
	wireType := arg.WireType

	// Handle the single character prefixed types produced by modcustom first.
	// These are case sensitive because "z" (narrow) and "Z" (wide) map to different things,
	// and "s" (short) and "S" (legacy string) mean different things.
	if wireType == "z" {
		return "z" + fmt.Sprint(val), nil
	} else if wireType == "Z" {
		return "Z" + fmt.Sprint(val), nil
	} else if wireType == "i" {
		return formatInt(val, "i")
	} else if wireType == "s" {
		return formatInt(val, "s")
	} else if wireType == "b" {
		return formatBinary(val)
	}

	upperWireType := strings.ToUpper(wireType)

	switch upperWireType {
	case "LPWSTR":
		return "Z" + fmt.Sprint(val), nil
	case "LPSTR", "S":
		return "z" + fmt.Sprint(val), nil
	case "BOOL":
		switch v := val.(type) {
		case bool:
			if v {
				return "i1", nil
			}
			return "i0", nil
		case string:
			b, err := strconv.ParseBool(v)
			if err != nil {
				return "", fmt.Errorf("invalid bool value %q", v)
			}
			if b {
				return "i1", nil
			}
			return "i0", nil
		case float64:
			if v != 0 {
				return "i1", nil
			}
			return "i0", nil
		}
	case "DWORD", "QWORD", "SIZE_T", "HANDLE", "UINT", "INT", "PORT":
		return formatInt(val, "i")
	case "SHORT", "WORD", "INT16":
		return formatInt(val, "s")
	case "BINARY":
		return formatBinary(val)
	}

	return fmt.Sprint(val), nil
}

func formatInt(val any, prefix string) (string, error) {
	switch v := val.(type) {
	case bool:
		if v {
			return prefix + "1", nil
		}
		return prefix + "0", nil
	case int:
		return prefix + strconv.FormatInt(int64(v), 10), nil
	case int32:
		return prefix + strconv.FormatInt(int64(v), 10), nil
	case int64:
		return prefix + strconv.FormatInt(v, 10), nil
	case float64:
		return prefix + strconv.FormatFloat(v, 'f', -1, 64), nil
	case string:
		num, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return "", fmt.Errorf("invalid numeric value %q", v)
		}
		return prefix + strconv.FormatFloat(num, 'f', -1, 64), nil
	}
	return "", fmt.Errorf("invalid int value %v", val)
}

func formatBinary(val any) (string, error) {
	switch v := val.(type) {
	case string:
		if decoded, err := base64.StdEncoding.DecodeString(v); err == nil {
			return "b" + hex.EncodeToString(decoded), nil
		}
		return "b" + hex.EncodeToString([]byte(v)), nil
	case []byte:
		return "b" + hex.EncodeToString(v), nil
	case []any:
		buf := make([]byte, 0, len(v))
		for _, b := range v {
			if num, ok := b.(float64); ok {
				buf = append(buf, byte(num))
			}
		}
		return "b" + hex.EncodeToString(buf), nil
	}
	return "", fmt.Errorf("invalid binary value %v", val)
}

// PackLinuxArgs mirrors lighthouse.PackArgs for the subset used by
// PackCoffArgs. The C agent packs the same format in c2_bof_pack_args.
func PackLinuxArgs(args []string) ([]byte, error) {
	if len(args) == 0 {
		return nil, nil
	}

	var body []byte
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
			body = appendU32(body, uint32(len(data)))
			body = append(body, data...)
		case 'i':
			v, err := strconv.ParseInt(arg[1:], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("pack int: %w", err)
			}
			body = appendU32(body, uint32(v))
		case 's':
			v, err := strconv.ParseInt(arg[1:], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("pack short: %w", err)
			}
			body = appendU16(body, uint16(v))
		case 'z':
			// Narrow string. Match the Windows COFFLoader ABI: length-prefixed
			// AND NUL-terminated, so BOFs that pass the extracted pointer to
			// BeaconPrintf("%s") do not read past the argument.
			b := append([]byte(arg[1:]), 0)
			body = appendU32(body, uint32(len(b)))
			body = append(body, b...)
		case 'Z':
			// Wide string: UTF-16LE plus a 2-byte terminator, matching the
			// Windows packCString/utf16Bytes convention.
			u := utf16.Encode([]rune(arg[1:]))
			buf := make([]byte, len(u)*2+2)
			for i, r := range u {
				buf[i*2] = byte(r)
				buf[i*2+1] = byte(r >> 8)
			}
			body = appendU32(body, uint32(len(buf)))
			body = append(body, buf...)
		default:
			return nil, fmt.Errorf("unknown arg prefix %q", arg[0])
		}
	}

	out := make([]byte, 4, 4+len(body))
	binary.LittleEndian.PutUint32(out, uint32(len(body)))
	out = append(out, body...)
	return out, nil
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v), byte(v>>8))
}
