package live

import (
	"testing"
)

// TestExitRunsShutdownHooksInLIFOOrder pins the contract of the centralized
// exit path: registered cleanup runs before the process terminates, most
// recently registered first. The actual termination is intercepted so the test
// binary survives.
func TestExitRunsShutdownHooksInLIFOOrder(t *testing.T) {
	originalExit := exitFunc
	defer func() { exitFunc = originalExit }()

	// Isolate the global hook list.
	savedHooks := snapshotAndResetHooks()
	defer restoreHooks(savedHooks)

	var order []string
	OnShutdown(func() { order = append(order, "first") })
	OnShutdown(func() { order = append(order, "second") })

	var gotCode int
	exitFunc = func(code int) { gotCode = code }

	Exit(7)

	if gotCode != 7 {
		t.Fatalf("Exit(7) terminated with code %d, want 7", gotCode)
	}
	if len(order) != 2 || order[0] != "second" || order[1] != "first" {
		t.Fatalf("shutdown hook order = %v, want [second first]", order)
	}
}

// TestExitClearsHooks verifies hooks registered for one exit do not run again
// on a second Exit call, which would otherwise double-run cleanup.
func TestExitClearsHooks(t *testing.T) {
	originalExit := exitFunc
	defer func() { exitFunc = originalExit }()

	savedHooks := snapshotAndResetHooks()
	defer restoreHooks(savedHooks)

	calls := 0
	OnShutdown(func() { calls++ })
	exitFunc = func(int) {}

	Exit(0)
	Exit(0)

	if calls != 1 {
		t.Fatalf("shutdown hook ran %d times across two exits, want 1", calls)
	}
}

// ResetHooks is not exported; this helper keeps the test self-contained.
func snapshotAndResetHooks() []func() {
	shutdownMu.Lock()
	defer shutdownMu.Unlock()
	saved := shutdownHooks
	shutdownHooks = nil
	return saved
}

func restoreHooks(saved []func()) {
	shutdownMu.Lock()
	shutdownHooks = saved
	shutdownMu.Unlock()
}
