//go:build linux && !android && (386 || amd64 || arm64)

package memmod

import (
	"errors"
	"fmt"
	"runtime"
)

// resolveWithLinuxHandle resolves a possibly versioned symbol through the
// process dynamic loader. It is used for external symbols whose dependency
// relationship demands an exact match rather than the relaxed lookup the
// in-memory symbol table performs.
func resolveWithLinuxHandle(api *linuxDynAPI, handle uintptr, name string, version string) (uintptr, error) {
	if api == nil || api.dlsym == 0 {
		return 0, errors.New("dlsym is unavailable")
	}
	nameBytes, err := cStringBytes(name)
	if err != nil {
		return 0, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if api.dlerror != 0 {
		_ = callExportFunction(api.dlerror)
	}

	var address uintptr
	if version != "" {
		if api.dlvsym == 0 {
			return 0, fmt.Errorf("dlvsym is unavailable for versioned symbol %s@%s", name, version)
		}
		versionBytes, err := cStringBytes(version)
		if err != nil {
			return 0, err
		}
		address = callExportFunction(api.dlvsym, handle, cStringPtr(nameBytes), cStringPtr(versionBytes))
		runtime.KeepAlive(versionBytes)
	} else {
		address = callExportFunction(api.dlsym, handle, cStringPtr(nameBytes))
	}
	runtime.KeepAlive(nameBytes)
	if api.dlerror != 0 {
		if err := lastDLErrorLocked(api); err != nil {
			return 0, err
		}
	}
	if address == 0 {
		return 0, fmt.Errorf("symbol %q resolved to nil", name)
	}
	return address, nil
}
