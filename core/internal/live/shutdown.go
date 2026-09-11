package live

import (
	"os"
	"sync"
)

// exitFunc terminates the process. It is a variable so tests can substitute a
// recorder instead of killing the test binary.
var exitFunc = os.Exit

// Shutdown hooks run, most recently registered first, when Exit is called.
var (
	shutdownMu    sync.Mutex
	shutdownHooks []func()
)

// OnShutdown registers a best-effort cleanup to run when the process exits via
// Exit. Registering is process-wide and intended to happen once during startup.
func OnShutdown(fn func()) {
	if fn == nil {
		return
	}
	shutdownMu.Lock()
	shutdownHooks = append(shutdownHooks, fn)
	shutdownMu.Unlock()
}

// Exit terminates the process with the given status code. It routes process
// termination through one point so library packages never call os.Exit
// directly, registered shutdown hooks always run, and tests can intercept the
// decision to terminate.
func Exit(code int) {
	shutdownMu.Lock()
	hooks := shutdownHooks
	shutdownHooks = nil
	shutdownMu.Unlock()

	for i := len(hooks) - 1; i >= 0; i-- {
		hooks[i]()
	}
	exitFunc(code)
}
