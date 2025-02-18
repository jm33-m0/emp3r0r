package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/cavaliergopher/grab/v3"
	version "github.com/hashicorp/go-version"
	"github.com/jm33-m0/emp3r0r/core/lib/cc/cli"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
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
		logging.Debugf("Parsing %s: %v", strconv.Quote(newVersion), versionErr)
		return false
	}
	currentV, versionErr := version.NewVersion(currentVersion)
	if versionErr != nil {
		logging.Debugf("Parsing %s: %v", strconv.Quote(currentVersion), versionErr)
		return false
	}

	return newV.GreaterThan(currentV)
}

// UpdateCC updates emp3r0r C2 server to the latest version
// force: force update even if the latest version is the same as the current one
func UpdateCC(cmd *cobra.Command, args []string) {
	force, _ := cmd.Flags().GetBool("force")
	logging.Infof("Requesting latest emp3r0r release from GitHub...")
	// get latest release
	tarballURL, checksum, err := GetTarballURL(force)
	if err != nil {
		logging.Errorf("Failed to get latest release: %v", err)
		return
	}

	// force update
	if force {
		logging.Warningf("Force update is enabled, updating to the latest version regardless of the current version")
	}

	// checksum
	logging.Infof("Checksum: %s", checksum)

	// download path
	path := "/tmp/emp3r0r.tar.zst"
	lock := fmt.Sprintf("%s.downloading", path)

	// check if lock exists
	if util.IsFileExist(lock) {
		logging.Errorf("lock file %s exists, another download is in progress, if it's not the case, manually remove the lock", lock)
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
		logging.Infof("The tarball is already downloaded, verifying checksum...")
		if !verify_checksum() {
			logging.Warningf("Checksum verification failed, redownloading...")
			need_download = true
			os.RemoveAll(path)
			os.RemoveAll("/tmp/emp3r0r-build")
		} else {
			logging.Printf("Checksum verification passed, installing...")
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
			logging.Errorf("failed to initialize HTTP client")
			return
		}
		req, downloadErr := grab.NewRequest(path, tarballURL)
		if downloadErr != nil {
			logging.Errorf("create grab request: %v", downloadErr)
			return
		}
		logging.Printf("Downloading %s to %s...", tarballURL, path)
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
					logging.Errorf("download finished with error: %v", downloadErr)
					return
				}
				if !verify_checksum() {
					logging.Errorf("checksum verification failed")
					return
				}
				logging.Successf("Saved %s to %s (%d bytes)", tarballURL, path, resp.Size())
			case <-t.C:
				logging.Infof("%.02f%% complete at %.02f KB/s", resp.Progress()*100, resp.BytesPerSecond()/1024)
			}
		}
	}

	logging.Infof("Installing emp3r0r...")
	install_cmd := fmt.Sprintf("bash -c 'tar -I zstd -xvf %s -C /tmp && cd /tmp/emp3r0r-build && sudo ./emp3r0r --install'", path)
	logging.Printf("Running installer command: %s. Please run `tmux kill-session -t emp3r0r` after installing", install_cmd)

	out, err := exec.Command("bash", "-c", install_cmd).CombinedOutput()
	if err != nil {
		logging.Errorf("failed to update emp3r0r: %s (%v)", out, err)
	}
	logging.Printf("%s", out)
	logging.Warningf("emp3r0r will stop in 2 seconds. Start it again to use the new version")
	cli.TmuxDeinitWindows()
}
