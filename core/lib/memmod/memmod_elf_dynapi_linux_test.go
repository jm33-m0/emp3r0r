//go:build linux && !android && (386 || amd64 || arm64)

package memmod

import (
	"errors"
	"testing"
)

func fakeSymbolLookup(symbols map[string]uintptr) func(string) (uintptr, error) {
	return func(symbol string) (uintptr, error) {
		if addr, ok := symbols[symbol]; ok && addr != 0 {
			return addr, nil
		}
		return 0, errors.New("not found")
	}
}

func TestChooseLinuxDynAPIPublic(t *testing.T) {
	lookup := fakeSymbolLookup(map[string]uintptr{
		"dlopen":  0x1000,
		"dlsym":   0x2000,
		"dlvsym":  0x3000,
		"dlclose": 0x4000,
		"dlerror": 0x5000,
		// Internal names are also present (glibc 2.34+); public wins.
		"__libc_dlopen_mode": 0x6000,
		"__libc_dlsym":       0x7000,
	})
	api, err := chooseLinuxDynAPI(lookup)
	if err != nil {
		t.Fatalf("chooseLinuxDynAPI: %v", err)
	}
	if api.internal {
		t.Fatal("selected internal mode when the public API was available")
	}
	if api.dlopen != 0x1000 || api.dlsym != 0x2000 || api.dlvsym != 0x3000 ||
		api.dlclose != 0x4000 || api.dlerror != 0x5000 {
		t.Fatalf("public entry points not copied: %+v", api)
	}
	if api.defaultHandle != 0 {
		t.Fatalf("public defaultHandle = %#x, want RTLD_DEFAULT (0)", api.defaultHandle)
	}
}

func TestChooseLinuxDynAPIInternalFallback(t *testing.T) {
	// A pre-2.34 glibc process: no public dl* in any loaded module, but the
	// glibc-internal set is present in libc.
	lookup := fakeSymbolLookup(map[string]uintptr{
		"__libc_dlopen_mode": 0x1000,
		"__libc_dlsym":       0x2000,
		"__libc_dlclose":     0x3000,
	})
	api, err := chooseLinuxDynAPI(lookup)
	if err != nil {
		t.Fatalf("chooseLinuxDynAPI: %v", err)
	}
	if !api.internal {
		t.Fatal("selected public mode without a public dlopen/dlsym")
	}
	if api.dlopen != 0x1000 || api.dlsym != 0x2000 || api.dlclose != 0x3000 {
		t.Fatalf("internal entry points not copied: %+v", api)
	}
	if api.dlvsym != 0 || api.dlerror != 0 {
		t.Fatalf("internal mode must not expose dlvsym/dlerror: %+v", api)
	}
	if api.defaultHandle != 0 {
		t.Fatalf("defaultHandle must be filled in by initLinuxDynAPI, got %#x", api.defaultHandle)
	}
}

func TestChooseLinuxDynAPIPublicNeedsDlsym(t *testing.T) {
	// Only dlopen resolves (e.g. a partial libdl); the loader must fall back
	// to the internal set rather than pick a half-usable public API.
	lookup := fakeSymbolLookup(map[string]uintptr{
		"dlopen":             0x1000,
		"__libc_dlopen_mode": 0x2000,
		"__libc_dlsym":       0x3000,
	})
	api, err := chooseLinuxDynAPI(lookup)
	if err != nil {
		t.Fatalf("chooseLinuxDynAPI: %v", err)
	}
	if !api.internal || api.dlopen != 0x2000 || api.dlsym != 0x3000 {
		t.Fatalf("expected internal fallback, got %+v", api)
	}
}

func TestChooseLinuxDynAPIUnavailable(t *testing.T) {
	if _, err := chooseLinuxDynAPI(fakeSymbolLookup(nil)); err == nil {
		t.Fatal("chooseLinuxDynAPI succeeded with no dynamic loader API")
	}
	// internal __libc_dlopen_mode without __libc_dlsym is unusable.
	lookup := fakeSymbolLookup(map[string]uintptr{"__libc_dlopen_mode": 0x1000})
	if _, err := chooseLinuxDynAPI(lookup); err == nil {
		t.Fatal("chooseLinuxDynAPI succeeded with only __libc_dlopen_mode")
	}
}
