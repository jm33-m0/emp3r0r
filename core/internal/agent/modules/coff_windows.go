//go:build windows

package modules

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/praetorian-inc/goffloader/src/coff"
	"github.com/praetorian-inc/goffloader/src/lighthouse"
)

// runCOFFModule executes a COFF/BOF payload using goffloader on Windows.
func runCOFFModule(payload []byte, invocation def.ResolvedInvocation) (string, error) {
	if invocation.Coff == nil {
		return "", fmt.Errorf("missing COFF invocation data")
	}

	args, err := packResolvedCoffArgs(invocation.Coff.Args)
	if err != nil {
		return "", err
	}

	packedArgs, err := lighthouse.PackArgs(args)
	if err != nil {
		return "", fmt.Errorf("packing BOF args: %w", err)
	}

	output, err := coff.Load(payload, packedArgs)
	if err != nil {
		return "", fmt.Errorf("executing COFF module: %w", err)
	}

	return output, nil
}

func packResolvedCoffArgs(args []def.ResolvedCoffArg) ([]string, error) {
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

func normalizeCoffValue(arg def.ResolvedCoffArg) (string, error) {
	wireType := strings.ToUpper(arg.WireType)
	val := arg.Value

	switch wireType {
	case "LPWSTR", "LPSTR":
		return fmt.Sprint(val), nil
	case "BOOL":
		switch v := val.(type) {
		case bool:
			return strconv.FormatBool(v), nil
		case string:
			b, err := strconv.ParseBool(v)
			if err != nil {
				return "", fmt.Errorf("invalid bool value %q", v)
			}
			return strconv.FormatBool(b), nil
		case float64:
			return strconv.FormatBool(v != 0), nil
		}
	case "DWORD", "QWORD", "SIZE_T", "HANDLE", "UINT", "INT", "PORT":
		switch v := val.(type) {
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64), nil
		case string:
			num, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return "", fmt.Errorf("invalid numeric value %q", v)
			}
			return strconv.FormatFloat(num, 'f', -1, 64), nil
		}
	case "BINARY":
		switch v := val.(type) {
		case string:
			if decoded, err := base64.StdEncoding.DecodeString(v); err == nil {
				return base64.StdEncoding.EncodeToString(decoded), nil
			}
			return base64.StdEncoding.EncodeToString([]byte(v)), nil
		case []byte:
			return base64.StdEncoding.EncodeToString(v), nil
		case []interface{}:
			buf := make([]byte, 0, len(v))
			for _, b := range v {
				if num, ok := b.(float64); ok {
					buf = append(buf, byte(num))
				}
			}
			return base64.StdEncoding.EncodeToString(buf), nil
		}
	}

	return fmt.Sprint(val), nil
}

// parseCOFFArgs extracts the space-delimited args= entry from an env list.
// Kept for compatibility with existing tests; new codepaths supply resolved args directly.
func parseCOFFArgs(env []string) ([]string, error) {
	var raw string
	for _, e := range env {
		if strings.HasPrefix(e, "args=") {
			raw = strings.TrimPrefix(e, "args=")
			break
		}
	}

	if raw == "" {
		return nil, fmt.Errorf("args not found in env")
	}

	return strings.Fields(raw), nil
}
