package cc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/cavaliergopher/grab/v3"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

const (
	LatestRelease = "https://api.github.com/repos/jm33-m0/emp3r0r/releases/latest"
)

func GetTarballURL() (string, error) {
	// get latest release
	resp, err := http.Get(LatestRelease)
	if err != nil {
		return "", err
	}

	// parse JSON
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var release struct {
		Assets []struct {
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &release); err != nil {
		return "", err
	}

	if len(release.Assets) == 0 {
		return "", fmt.Errorf("no assets found in the latest release")
	}

	return release.Assets[0].BrowserDownloadURL, nil
}

func UpdateCC() (err error) {
	CliPrintInfo("Requesting latest emp3r0r release from GitHub...")
	// get latest release
	tarballURL, err := GetTarballURL()
	if err != nil {
		return err
	}

	// download path
	path := "/tmp/emp3r0r.tar.zst"
	lock := fmt.Sprintf("%s.downloading", path)

	// check if lock exists
	if util.IsFileExist(lock) {
		err = fmt.Errorf("lock file %s exists, another download is in progress, if it's not the case, manually remove the lock", lock)
		return
	}

	// create lock file
	os.Create(lock)
	defer os.Remove(lock)

	// download tarball using grab
	client := grab.NewClient()
	if client.HTTPClient == nil {
		err = fmt.Errorf("failed to initialize HTTP client")
		return
	}
	req, err := grab.NewRequest(path, tarballURL)
	if err != nil {
		err = fmt.Errorf("create grab request: %v", err)
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
			err = resp.Err()
			if err != nil {
				err = fmt.Errorf("download finished with error: %v", err)
				return
			}
			CliPrintSuccess("Saved %s to %s (%d bytes)", tarballURL, path, resp.Size())
		case <-t.C:
			CliPrintInfo("%.02f%% complete at %.02f KB/s", resp.Progress()*100, resp.BytesPerSecond()/1024)
		}
	}
	CliPrintInfo("Download complete, installing emp3r0r...")

	install_cmd := fmt.Sprintf("bash -c 'tar -I zstd -xvf %s -C /tmp && cd /tmp/emp3r0r-build && sudo ./emp3r0r --install; sleep 5'", path)
	CliPrint("Running installer command: %s", install_cmd)
	err = exec.Command("x-terminal-emulator", "-e", install_cmd).Run()
	if err != nil {
		return fmt.Errorf("failed to update emp3r0r: %v", err)
	}

	return nil
}
