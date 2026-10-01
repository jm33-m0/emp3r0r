//go:build cgo && linux && !android && (386 || amd64 || arm64)

package memmod

import "testing"

// A cgo build is dynamically linked against the system libc, so the loader
// must always be able to bootstrap a dynamic-loader API from the process
// image. This is the regression guard for pre-2.34 glibc, where the public
// dlopen/dlsym are not linked into a Go process and only the glibc-internal
// __libc_* entry points are reachable.
func TestLinuxDynAPIAvailableWithCgo(t *testing.T) {
	api, err := getLinuxDynAPI()
	if err != nil {
		t.Fatalf("getLinuxDynAPI with cgo (libc is mapped): %v", err)
	}
	if api.dlopen == 0 || api.dlsym == 0 {
		t.Fatalf("dynamic loader API is incomplete: %+v", api)
	}
	if api.internal {
		t.Log("dynamic loader API: glibc-internal __libc_*")
		// Internal mode has no RTLD_DEFAULT and must have bound the global
		// scope handle, or every bare-name lookup would fault.
		if api.defaultHandle == 0 {
			t.Fatal("internal mode selected without a global scope handle")
		}
	} else {
		t.Log("dynamic loader API: public dl*")
		if api.defaultHandle != 0 {
			t.Fatalf("public mode defaultHandle = %#x, want RTLD_DEFAULT (0)", api.defaultHandle)
		}
	}
}

// __libc_dlsym returns a GNU IFUNC's resolver, unlike the public dlsym which
// invokes it. finishInternalIFUNC has to complete the job, or imports such as
// memset/memcpy bind to a function that does nothing.
func TestFinishInternalIFUNC(t *testing.T) {
	modules, err := runtimeModules()
	if err != nil {
		t.Skipf("cannot read runtime modules: %v", err)
	}
	var libcPath string
	var libcBase uintptr
	for _, module := range modules {
		if libcPathScore(module.path) >= 90 {
			libcPath, libcBase = module.path, module.base
			break
		}
	}
	if libcPath == "" {
		t.Skip("no libc mapped in this process")
	}

	ifuncs := loadIFUNCOffsets(libcPath)
	if len(ifuncs) == 0 {
		t.Skipf("libc %s uses no GNU IFUNC symbols", libcPath)
	}
	for _, name := range []string{"memset", "memcpy", "strlen", "strcmp", "memchr"} {
		off, ok := ifuncs[name]
		if !ok {
			continue
		}
		resolver := libcBase + off
		impl := finishInternalIFUNC(modules, name, resolver)
		if impl == 0 || impl == resolver {
			t.Fatalf("finishInternalIFUNC(%s) = %#x, want a distinct implementation (resolver %#x)", name, impl, resolver)
		}
		return
	}
	t.Fatalf("no known IFUNC name among the %d offsets parsed from %s", len(ifuncs), libcPath)
}
