package script

import (
	"encoding/base64"
	"fmt"

	"go.starlark.net/starlark"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// Binary-safe byte plumbing for Starlark modules.
//
// Starlark strings are arbitrary bytes in this codebase, but the engine's
// native bytes() builtin transcodes them as UTF-8 (corrupting >=0x80
// values), so binary payloads must travel as starlark.Bytes end-to-end.
// These helpers accept both starlark.String and starlark.Bytes and always
// return Bytes, letting modules move binary data (e.g. cifs download
// chunks) without UTF-8 corruption.

func init() {
	RegisterAPI("bytes_to_b64", starlarkBytesToB64)
	RegisterAPI("b64_to_bytes", starlarkB64ToBytes)
	RegisterAPI("write_bytes", starlarkWriteBytes)
}

// valueToBytes converts a starlark value to raw bytes:
//   - starlark.Bytes      – taken as-is (binary-safe)
//   - starlark.String     – its raw byte content
//   - list/tuple of ints  – one byte per element (what win_read_mem returns)
func valueToBytes(v starlark.Value) ([]byte, bool) {
	switch val := v.(type) {
	case starlark.Bytes:
		return []byte(val), true
	case starlark.String:
		return []byte(val), true
	case starlark.Iterable:
		iter := val.Iterate()
		defer iter.Done()
		var elem starlark.Value
		buf := make([]byte, 0, 64)
		for iter.Next(&elem) {
			i, err := starlark.AsInt32(elem)
			if err != nil || i < 0 || i > 255 {
				return nil, false
			}
			buf = append(buf, byte(i))
		}
		return buf, true
	}
	return nil, false
}

// starlarkBytesToB64 encodes a binary string/bytes value as base64.
// Used to verify upload integrity: the script hashes the source payload and
// the downloaded copy of the remote file and compares the base64 digests.
func starlarkBytesToB64(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var dataVal starlark.Value
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "data", &dataVal); err != nil {
		return starlark.None, err
	}
	data, ok := valueToBytes(dataVal)
	if !ok {
		return starlark.None, fmt.Errorf("%s: data must be string or bytes, got %s", fn.Name(), dataVal.Type())
	}
	return starlark.String(base64.StdEncoding.EncodeToString(data)), nil
}

// starlarkB64ToBytes decodes base64 into a binary bytes value.
// Accepts a single base64 string, a list/tuple of base64 strings (each
// element decoded separately, then concatenated — win_read_mem chunks come
// back individually padded, so they must not be joined before decoding), or
// raw bytes (returned unchanged). This is the binary-safe exit from the
// base64 representation the script accumulates for a cifs download.
func starlarkB64ToBytes(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var dataVal starlark.Value
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "data", &dataVal); err != nil {
		return starlark.None, err
	}

	decode := func(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

	var out []byte
	switch val := dataVal.(type) {
	case starlark.Bytes:
		out = []byte(val) // already binary, pass through
	case starlark.Iterable:
		iter := val.Iterate()
		defer iter.Done()
		var elem starlark.Value
		for iter.Next(&elem) {
			s, ok := starlark.AsString(elem)
			if !ok {
				return starlark.None, fmt.Errorf("%s: list elements must be base64 strings, got %s", fn.Name(), elem.Type())
			}
			chunk, err := decode(s)
			if err != nil {
				return starlark.None, fmt.Errorf("%s: %v", fn.Name(), err)
			}
			out = append(out, chunk...)
		}
	default:
		s, ok := starlark.AsString(dataVal)
		if !ok {
			return starlark.None, fmt.Errorf("%s: expected base64 string, list of strings, or bytes, got %s", fn.Name(), dataVal.Type())
		}
		var err error
		out, err = decode(s)
		if err != nil {
			return starlark.None, fmt.Errorf("%s: %v", fn.Name(), err)
		}
	}
	return starlark.Bytes(out), nil
}

// starlarkWriteBytes writes a bytes/string value to a local or mem:///
// path via the agent's centralised file writer (WriteFileAgent), which
// handles memfs storage transparently and runs under the module's token.
// Returning the written size lets the script verify the length.
func starlarkWriteBytes(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	var dataVal starlark.Value
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "path", &path, "data", &dataVal); err != nil {
		return starlark.None, err
	}
	data, ok := valueToBytes(dataVal)
	if !ok {
		return starlark.None, fmt.Errorf("%s: data must be string or bytes, got %s", fn.Name(), dataVal.Type())
	}
	if err := util.WriteFileAgent(path, data, 0o644); err != nil {
		return starlark.None, fmt.Errorf("%s: write %s: %v", fn.Name(), path, err)
	}
	return starlark.MakeInt(len(data)), nil
}
