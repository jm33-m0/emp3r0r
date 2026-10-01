//go:build linux && !android && (386 || amd64 || arm64)

package memmod

import (
	"errors"
	"runtime"
)

// Linux offers two equivalent sets of dynamic-loader entry points:
//
//   - the public dlopen/dlsym/dlvsym/dlerror/dlclose API, which lives in
//     libdl.so.2 before glibc 2.34 and moved into libc.so.6 in glibc 2.34;
//   - the glibc-internal __libc_dlopen_mode/__libc_dlsym/__libc_dlclose,
//     exported by libc.so.6 on every glibc before 2.34 (in 2.34+ they are
//     hidden).
//
// A Go process does not link libdl.so.2, so on pre-2.34 glibc the public
// names are simply not present among the loaded modules. initLinuxDynAPI
// picks whichever set resolves from the process image, so one binary works
// on both old and new glibc without ever loading libdl.
func initLinuxDynAPI() error {
	modules, err := runtimeModules()
	if err != nil {
		return err
	}

	api, err := chooseLinuxDynAPI(func(symbol string) (uintptr, error) {
		return resolveRuntimeAPISymbol(modules, symbol)
	})
	if err != nil {
		return err
	}

	if api.internal {
		// __libc_dlsym dereferences its handle (it has no RTLD_DEFAULT path
		// like the public dlsym does), so bind the main program's global
		// scope once and use that for bare-name lookups. An empty name is how
		// dlopen(NULL) reaches _dl_open and must not be a NULL pointer.
		handle, err := internalGlobalHandle(api.dlopen)
		if err != nil {
			return err
		}
		api.defaultHandle = handle
	}

	linuxAPI = api
	return nil
}

// chooseLinuxDynAPI selects the public dl* API when both dlopen and dlsym are
// present, otherwise the glibc-internal __libc_* API. lookup resolves a symbol
// name against the process's loaded modules.
func chooseLinuxDynAPI(lookup func(string) (uintptr, error)) (linuxDynAPI, error) {
	if api, ok := publicLinuxDynAPI(lookup); ok {
		return api, nil
	}
	if api, ok := internalLinuxDynAPI(lookup); ok {
		return api, nil
	}
	return linuxDynAPI{}, errors.New("no dynamic loader API in the loaded modules: neither public dlopen/dlsym nor glibc-internal __libc_dlopen_mode/__libc_dlsym resolved")
}

func publicLinuxDynAPI(lookup func(string) (uintptr, error)) (linuxDynAPI, bool) {
	dlopenAddr, err := lookup("dlopen")
	if err != nil || dlopenAddr == 0 {
		return linuxDynAPI{}, false
	}
	dlsymAddr, err := lookup("dlsym")
	if err != nil || dlsymAddr == 0 {
		return linuxDynAPI{}, false
	}
	// dlerror/dlvsym/dlclose are best-effort: the loader degrades gracefully
	// when they are missing.
	dlerrorAddr, _ := lookup("dlerror")
	dlvsymAddr, _ := lookup("dlvsym")
	dlcloseAddr, _ := lookup("dlclose")
	return linuxDynAPI{
		dlopen:        dlopenAddr,
		dlsym:         dlsymAddr,
		dlvsym:        dlvsymAddr,
		dlclose:       dlcloseAddr,
		dlerror:       dlerrorAddr,
		defaultHandle: 0, // RTLD_DEFAULT
	}, true
}

// internalLinuxDynAPI returns the glibc-internal entry points. defaultHandle
// is left for initLinuxDynAPI to fill in; it cannot be zero because
// __libc_dlsym would fault on it.
func internalLinuxDynAPI(lookup func(string) (uintptr, error)) (linuxDynAPI, bool) {
	dlopenAddr, err := lookup("__libc_dlopen_mode")
	if err != nil || dlopenAddr == 0 {
		return linuxDynAPI{}, false
	}
	dlsymAddr, err := lookup("__libc_dlsym")
	if err != nil || dlsymAddr == 0 {
		return linuxDynAPI{}, false
	}
	dlcloseAddr, _ := lookup("__libc_dlclose")
	return linuxDynAPI{
		dlopen:   dlopenAddr,
		dlsym:    dlsymAddr,
		dlclose:  dlcloseAddr,
		internal: true,
	}, true
}

// internalGlobalHandle calls __libc_dlopen_mode("", RTLD_NOW|RTLD_GLOBAL) and
// returns the main program's global-scope link map.
func internalGlobalHandle(dlopenAddr uintptr) (uintptr, error) {
	name, err := cStringBytes("")
	if err != nil {
		return 0, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	handle := callExportFunction(dlopenAddr, cStringPtr(name), uintptr(rtldNow|rtldGlobal))
	runtime.KeepAlive(name)
	if handle == 0 {
		return 0, errors.New("__libc_dlopen_mode(\"\") did not return a global scope handle")
	}
	return handle, nil
}
