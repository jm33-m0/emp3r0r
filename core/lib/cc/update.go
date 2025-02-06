//go:build linux
// +build linux

package cc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cavaliergopher/grab/v3"
	version "github.com/hashicorp/go-version"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

const (
	LatestRelease = "https://api.github.com/repos/jm33-m0/emp3r0r/releases/latest"
)

func GetTarballURL(force bool) (url, checksum string, err error) {
	// get latest release
	resp, err := http.Get(LatestRelease)
	if err != nil {
		return
	}

	// parse JSON
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err = json.Unmarshal(body, &release); err != nil {
		return
	}

	// check if the release is newer
	if !isNewerVersion(release.TagName, emp3r0r_def.Version) && !force {
		err = fmt.Errorf("no newer version available")
		return
	}

	if len(release.Assets) == 0 {
		err = fmt.Errorf("no assets found in the latest release")
		return
	}

	if len(release.Assets) > 1 {
		// read the checksum file
		checksumFile := release.Assets[1].BrowserDownloadURL
		resp, err = http.Get(checksumFile)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		respBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			err = fmt.Errorf("failed to read checksum file: %v", readErr)
			return
		}
		checksum = string(respBody)
		if checksum == "" {
			err = fmt.Errorf("checksum is empty")
			return
		}
	}

	url = release.Assets[0].BrowserDownloadURL

	return
}

func isNewerVersion(newVersion, currentVersion string) bool {
	// strip 'v' prefix
	newVersion = strings.TrimPrefix(newVersion, "v")
	currentVersion = strings.TrimPrefix(currentVersion, "v")

	// parse and compare
	newV, versionErr := version.NewVersion(newVersion)
	if versionErr != nil {
		CliPrintDebug("Parsing %s: %v", strconv.Quote(newVersion), versionErr)
		return false
	}
	currentV, versionErr := version.NewVersion(currentVersion)
	if versionErr != nil {
		CliPrintDebug("Parsing %s: %v", strconv.Quote(currentVersion), versionErr)
		return false
	}

	return newV.GreaterThan(currentV)
}

// UpdateCC updates emp3r0r C2 server to the latest version
// force: force update even if the latest version is the same as the current one
func UpdateCC(cmd *cobra.Command, args []string) {
	force, _ := cmd.Flags().GetBool("force")
	CliPrintInfo("Requesting latest emp3r0r release from GitHub...")
	// get latest release
	tarballURL, checksum, err := GetTarballURL(force)
	if err != nil {
		CliPrintError("Failed to get latest release: %v", err)
		return
	}

	// force update
	if force {
		CliPrintWarning("Force update is enabled, updating to the latest version regardless of the current version")
	}

	// checksum
	CliPrintInfo("Checksum: %s", checksum)

	// download path
	path := "/tmp/emp3r0r.tar.zst"
	lock := fmt.Sprintf("%s.downloading", path)

	// check if lock exists
	if util.IsFileExist(lock) {
		CliPrintError("lock file %s exists, another download is in progress, if it's not the case, manually remove the lock", lock)
		return
	}
	os.Remove(lock)

	verify_checksum := func() bool {
		file_checksum := tun.SHA256SumFile(path)
		return file_checksum == checksum
	}
	need_download := false

	// check if target file exists
	if util.IsFileExist(path) {
		// verify checksum
		CliPrintInfo("The tarball is already downloaded, verifying checksum...")
		if !verify_checksum() {
			CliPrintWarning("Checksum verification failed, redownloading...")
			need_download = true
			os.RemoveAll(path)
			os.RemoveAll("/tmp/emp3r0r-build")
		} else {
			CliPrint("Checksum verification passed, installing...")
		}
	} else {
		need_download = true
	}

	// download tarball
	if need_download {
		// create lock file
		os.Create(lock)
		defer os.Remove(lock)

		// download tarball using grab
		client := grab.NewClient()
		if client.HTTPClient == nil {
			CliPrintError("failed to initialize HTTP client")
			return
		}
		req, downloadErr := grab.NewRequest(path, tarballURL)
		if downloadErr != nil {
			CliPrintError("create grab request: %v", downloadErr)
			return
		}
		CliPrint("Downloading %s to %s...", tarballURL, path)
		resp := client.Do(req)

		// progress
		t := time.NewTicker(5 * time.Second)
		defer func() {
			t.Stop()
			if !util.IsExist(path) {
				err = fmt.Errorf("target file '%s' does not exist, download may have failed", path)
			}
		}()
		for !resp.IsComplete() {
			select {
			case <-resp.Done:
				downloadErr = resp.Err()
				if downloadErr != nil {
					CliPrintError("download finished with error: %v", downloadErr)
					return
				}
				if !verify_checksum() {
					CliPrintError("checksum verification failed")
					return
				}
				CliPrintSuccess("Saved %s to %s (%d bytes)", tarballURL, path, resp.Size())
			case <-t.C:
				CliPrintInfo("%.02f%% complete at %.02f KB/s", resp.Progress()*100, resp.BytesPerSecond()/1024)
			}
		}
	}

	CliPrintInfo("Installing emp3r0r...")
	install_cmd := fmt.Sprintf("bash -c 'tar -I zstd -xvf %s -C /tmp && cd /tmp/emp3r0r-build && sudo ./emp3r0r --install; sleep 5'", path)
	CliPrint("Running installer command: %s. Please run `tmux kill-session -t emp3r0r` after installing", install_cmd)

	wrapper, err := exec.LookPath("x-terminal-emulator")
	if err != nil {
		CliPrintError("%v. your distribution is unsupported", err)
		return
	}
	exec_cmd := exec.Command(wrapper, "-e", install_cmd)
	exec_cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, err := exec_cmd.CombinedOutput()
	if err != nil {
		CliPrintError("failed to update emp3r0r: %v: %s", err, out)
	}
}
