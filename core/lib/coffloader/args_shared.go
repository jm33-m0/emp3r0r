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

// PackCoffArgs converts CoffArg values to the lighthouse wire format.
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
	wireType := strings.ToUpper(arg.WireType)
	val := arg.Value

	switch wireType {
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
		switch v := val.(type) {
		case int:
			return "i" + strconv.FormatInt(int64(v), 10), nil
		case int32:
			return "i" + strconv.FormatInt(int64(v), 10), nil
		case int64:
			return "i" + strconv.FormatInt(v, 10), nil
		case float64:
			return "i" + strconv.FormatFloat(v, 'f', -1, 64), nil
		case string:
			num, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return "", fmt.Errorf("invalid numeric value %q", v)
			}
			return "i" + strconv.FormatFloat(num, 'f', -1, 64), nil
		}
	case "SHORT", "WORD", "INT16":
		switch v := val.(type) {
		case int:
			return "s" + strconv.FormatInt(int64(v), 10), nil
		case int32:
			return "s" + strconv.FormatInt(int64(v), 10), nil
		case int64:
			return "s" + strconv.FormatInt(v, 10), nil
		case float64:
			return "s" + strconv.FormatFloat(v, 'f', -1, 64), nil
		case string:
			num, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return "", fmt.Errorf("invalid numeric value %q", v)
			}
			return "s" + strconv.FormatFloat(num, 'f', -1, 64), nil
		}
	case "BINARY":
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
	}

	return fmt.Sprint(val), nil
}
