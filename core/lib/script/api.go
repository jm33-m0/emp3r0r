package script

import (
	"fmt"

	"go.starlark.net/starlark"
)

// StarlarkAPI defines a Go function signature exposed to Starlark.
type StarlarkAPI func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error)

// Global registry for Starlark APIs
var apis = make(map[string]StarlarkAPI)

// RegisterAPI registers a Go function under the given name to be callable from Starlark scripts.
func RegisterAPI(name string, api StarlarkAPI) {
	apis[name] = api
}

// getAPIs returns the mapping of registered Go functions exposed to Starlark
func getAPIs() starlark.StringDict {
	dict := make(starlark.StringDict)
	for name, fn := range apis {
		dict[name] = starlark.NewBuiltin(name, fn)
	}
	return dict
}

var builtInAPIs = map[string]StarlarkAPI{
	"read_file":        starlarkReadFile,
	"write_file":       starlarkWriteFile,
	"list_dir":         starlarkListDir,
	"exists":           starlarkExists,
	"mkdir":            starlarkMkdir,
	"remove":           starlarkRemove,
	"http_get":         starlarkHTTPGet,
	"http_post":        starlarkHTTPPost,
	"exec_cmd":         starlarkExecCmd,
	"crypto_hash":      starlarkCryptoHash,
	"sprintf":          starlarkSprintf,
	"hex":              starlarkHex,
	"str_split":        starlarkStrSplit,
	"str_join":         starlarkStrJoin,
	"str_replace":      starlarkStrReplace,
	"str_contains":     starlarkStrContains,
	"str_trim":         starlarkStrTrim,
	"str_lower":        starlarkStrLower,
	"str_upper":        starlarkStrUpper,
	"str_startswith":   starlarkStrStartsWith,
	"str_endswith":     starlarkStrEndsWith,
	"str_pad":          starlarkStrPad,
	"str_index":        starlarkStrIndex,
	"pad":              starlarkStrPad,
	"read_u8":          starlarkReadUint8,
	"read_uint8":       starlarkReadUint8,
	"read_u16":         starlarkReadUint16,
	"read_uint16":      starlarkReadUint16,
	"read_u32":         starlarkReadUint32,
	"read_uint32":      starlarkReadUint32,
	"read_u64":         starlarkReadUint64,
	"read_uint64":      starlarkReadUint64,
	"read_ptr":         starlarkReadUint64,
	"read_i32":         starlarkReadInt32,
	"read_int32":       starlarkReadInt32,
	"read_wstring":     starlarkReadWString,
	"read_cstring":     starlarkReadCString,
	"read_ansi_string": starlarkReadCString,
	"write_byte":       starlarkWriteUint8,
	"write_u8":         starlarkWriteUint8,
	"write_uint8":      starlarkWriteUint8,
	"write_u16":        starlarkWriteUint16,
	"write_uint16":     starlarkWriteUint16,
	"write_u32":        starlarkWriteUint32,
	"write_uint32":     starlarkWriteUint32,
	"write_u64":        starlarkWriteUint64,
	"write_uint64":     starlarkWriteUint64,
	"write_ptr":        starlarkWriteUint64,
	"utf16_ptr":        starlarkUTF16Ptr,
	"cstring_ptr":      starlarkCStringPtr,
	"ansi_ptr":         starlarkCStringPtr,
	"win_call":         starlarkWinCall,
	"win_alloc":        starlarkWinAlloc,
	"win_free":         starlarkWinFree,
	"win_read_mem":     starlarkWinReadMem,
	"sys_call":         starlarkSysCall,
	"sys_alloc":        starlarkSysAlloc,
	"sys_free":         starlarkSysFree,
	"sys_read_mem":     starlarkSysReadMem,
	"lin_syscall":      starlarkSysCall,
	"lin_alloc":        starlarkSysAlloc,
	"lin_free":         starlarkSysFree,
	"lin_read_mem":     starlarkSysReadMem,
	"linux_syscall":    starlarkSysCall,
	"linux_alloc":      starlarkSysAlloc,
	"linux_free":       starlarkSysFree,
	"linux_read_mem":   starlarkSysReadMem,
}

func init() {
	for name, fn := range builtInAPIs {
		RegisterAPI(name, fn)
	}
}

func starlarkSprintf(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if len(args) == 0 {
		return starlark.None, fmt.Errorf("sprintf requires at least a format string")
	}
	format, ok := starlark.AsString(args[0])
	if !ok {
		return starlark.None, fmt.Errorf("sprintf first argument must be a format string")
	}
	goArgs := make([]any, 0, len(args)-1)
	for i := 1; i < len(args); i++ {
		switch v := args[i].(type) {
		case starlark.Int:
			if val, ok := v.Int64(); ok {
				goArgs = append(goArgs, val)
			} else if val, ok := v.Uint64(); ok {
				goArgs = append(goArgs, val)
			} else {
				goArgs = append(goArgs, v.String())
			}
		case starlark.String:
			goArgs = append(goArgs, string(v))
		case starlark.Bool:
			goArgs = append(goArgs, bool(v))
		case starlark.Float:
			goArgs = append(goArgs, float64(v))
		default:
			goArgs = append(goArgs, v.String())
		}
	}
	return starlark.String(fmt.Sprintf(format, goArgs...)), nil
}

func starlarkHex(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if len(args) != 1 {
		return starlark.None, fmt.Errorf("hex requires exactly 1 argument")
	}
	v, ok := args[0].(starlark.Int)
	if !ok {
		return starlark.None, fmt.Errorf("hex argument must be an integer")
	}
	if val, ok := v.Uint64(); ok {
		return starlark.String(fmt.Sprintf("0x%x", val)), nil
	}
	if val, ok := v.Int64(); ok {
		return starlark.String(fmt.Sprintf("0x%x", val)), nil
	}
	return starlark.String(v.String()), nil
}
