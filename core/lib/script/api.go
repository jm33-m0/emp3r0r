package script

import (
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
	"read_file":      starlarkReadFile,
	"write_file":     starlarkWriteFile,
	"list_dir":       starlarkListDir,
	"exists":         starlarkExists,
	"mkdir":          starlarkMkdir,
	"remove":         starlarkRemove,
	"http_get":       starlarkHTTPGet,
	"http_post":      starlarkHTTPPost,
	"exec_cmd":       starlarkExecCmd,
	"list_processes": starlarkListProcesses,
	"crypto_hash":    starlarkCryptoHash,
	"win_call":       starlarkWinCall,
	"win_alloc":      starlarkWinAlloc,
	"win_free":       starlarkWinFree,
	"win_read_mem":   starlarkWinReadMem,
}

func init() {
	for name, fn := range builtInAPIs {
		RegisterAPI(name, fn)
	}
}
