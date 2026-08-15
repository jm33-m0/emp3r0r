package coffloader

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
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
