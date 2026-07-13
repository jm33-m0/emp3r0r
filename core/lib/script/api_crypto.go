package script

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"strings"

	"go.starlark.net/starlark"
)

func starlarkCryptoHash(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var algo string
	var dataVal starlark.Value
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "algo", &algo, "data", &dataVal); err != nil {
		return starlark.None, err
	}

	var data []byte
	if s, ok := starlark.AsString(dataVal); ok {
		data = []byte(s)
	} else if bytesVal, ok := dataVal.(starlark.Bytes); ok {
		data = []byte(bytesVal)
	} else {
		return starlark.None, fmt.Errorf("data must be a string or bytes, got %T", dataVal)
	}

	var hashBytes []byte
	switch strings.ToLower(algo) {
	case "md5":
		h := md5.Sum(data)
		hashBytes = h[:]
	case "sha1":
		h := sha1.Sum(data)
		hashBytes = h[:]
	case "sha256":
		h := sha256.Sum256(data)
		hashBytes = h[:]
	default:
		return starlark.None, fmt.Errorf("unsupported algorithm: %s", algo)
	}

	return starlark.String(fmt.Sprintf("%x", hashBytes)), nil
}
