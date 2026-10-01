//go:build !windows && !(linux && !android && (386 || amd64 || arm64))

package memmod

import (
	"fmt"
	"runtime"
)

// Module is an opaque in-memory shared-library handle on platforms without a
// loader backend.
type Module struct{}

// BaseAddr is present so callers can build on every platform.
func (module *Module) BaseAddr() uintptr { return 0 }

// LoadLibrary reports that in-memory shared-library loading is unavailable.
func LoadLibrary(data []byte) (*Module, error) {
	_ = data
	return nil, unsupportedPlatformError()
}

// Free is a no-op on unsupported platforms.
func (module *Module) Free() {}

// CallExport reports that in-memory shared-library loading is unavailable.
func (module *Module) CallExport(name string) error {
	_ = name
	return unsupportedPlatformError()
}

// CallExportWithArgs reports that argument-bearing export calls are unsupported.
//
//go:uintptrescapes
func (module *Module) CallExportWithArgs(name string, args ...uintptr) (uintptr, error) {
	_, _ = name, args
	return 0, unsupportedPlatformError()
}

// ProcAddressByName reports that in-memory shared-library loading is unavailable.
func (module *Module) ProcAddressByName(name string) (uintptr, error) {
	_ = name
	return 0, unsupportedPlatformError()
}

// ProcAddressByOrdinal reports that in-memory shared-library loading is unavailable.
func (module *Module) ProcAddressByOrdinal(ordinal uint16) (uintptr, error) {
	_ = ordinal
	return 0, unsupportedPlatformError()
}

func unsupportedPlatformError() error {
	return fmt.Errorf("memmod shared-library loader is unsupported on %s/%s", runtime.GOOS, runtime.GOARCH)
}
