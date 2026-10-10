package modules

import (
	"testing"
	"time"

	c2context "github.com/jm33-m0/emp3r0r/core/internal/cc/context"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// armModuleRun installs a test runner for name and restores the global module
// selection and active target when the test finishes. The runner reports every
// invocation on the returned channel, so a test can assert whether ModuleRun
// dispatched the module or rejected it before dispatch.
func armModuleRun(t *testing.T, name string) <-chan struct{} {
	t.Helper()

	prevModules := live.ActiveModule
	prevActive := live.GetActiveAgent()
	// Register a fresh module definition so the platform gate under test has
	// something to look at, and keep it out of the shared registry afterwards.
	mod := &def.ModuleConfig{Name: name}
	def.Modules.Store(name, mod)

	called := make(chan struct{}, 4)
	registerModuleRunner(name, func(*c2context.C2Context) { called <- struct{}{} })
	t.Cleanup(func() {
		deleteModuleRunner(name)
		def.Modules.Delete(name)
		live.ActiveModule = prevModules
		live.SetActiveAgent(prevActive)
	})

	return called
}

// ranWithin reports whether the module runner was invoked within d.
func ranWithin(called <-chan struct{}, d time.Duration) bool {
	select {
	case <-called:
		return true
	case <-time.After(d):
		return false
	}
}

// TestModuleRunLocalIgnoresPlatformAndTarget is the regression test for local
// C2 modules being rejected by the target platform gate. A local module runs on
// the operator host and never reaches an agent, so it must run regardless of
// any selected target's OS (or the absence of a target).
func TestModuleRunLocalIgnoresPlatformAndTarget(t *testing.T) {
	const name = "test_local_platform_gate"
	called := armModuleRun(t, name)
	mod, _ := def.GetModule(name)
	mod.IsLocal = true
	mod.Platform = "Windows"

	// No target at all.
	live.SetActiveAgent(nil)
	live.ActiveModule = mod
	ModuleRun(&c2context.C2Context{})
	if !ranWithin(called, 2*time.Second) {
		t.Fatalf("local module %s did not run with no active target", name)
	}

	// A target of a different OS must not block a local module either.
	live.SetActiveAgent(&def.Emp3r0rAgent{Tag: "linux-target", GOOS: "linux"})
	ModuleRun(&c2context.C2Context{Target: live.GetActiveAgent()})
	if !ranWithin(called, 2*time.Second) {
		t.Fatalf("local module %s did not run with a Linux target while its Platform is Windows", name)
	}
}

// TestModuleRunAgentEnforcesPlatformAndTarget verifies the gate still applies
// where it belongs: an agent module must not run against a mismatched target
// OS, and must not run without a target.
func TestModuleRunAgentEnforcesPlatformAndTarget(t *testing.T) {
	const name = "test_agent_platform_gate"
	called := armModuleRun(t, name)
	mod, _ := def.GetModule(name)
	mod.IsLocal = false
	mod.Platform = "Windows"

	live.SetActiveAgent(&def.Emp3r0rAgent{Tag: "linux-target", GOOS: "linux"})
	live.ActiveModule = mod
	ModuleRun(&c2context.C2Context{Target: live.GetActiveAgent()})
	if ranWithin(called, 200*time.Millisecond) {
		t.Fatalf("agent Windows module %s ran on a Linux target", name)
	}

	// Generic modules pass the OS gate but still need a target to run on.
	mod.Platform = "Generic"
	live.SetActiveAgent(nil)
	ModuleRun(&c2context.C2Context{})
	if ranWithin(called, 200*time.Millisecond) {
		t.Fatalf("agent module %s ran without an active target", name)
	}
}
