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
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

const (
	LatestRelease = "https://api.github.com/repos/jm33-m0/emp3r0r/releases/latest"
)

func GetTarballURL() (url, checksum string, err error) {
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
		Assets []struct {
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err = json.Unmarshal(body, &release); err != nil {
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

func UpdateCC() (err error) {
	CliPrintInfo("Requesting latest emp3r0r release from GitHub...")
	// get latest release
	tarballURL, checksum, err := GetTarballURL()
	if err != nil {
		return err
	}

	// checksum
	CliPrintInfo("Checksum: %s", checksum)

	// download path
	path := "/tmp/emp3r0r.tar.zst"
	lock := fmt.Sprintf("%s.downloading", path)

	// check if lock exists
	if util.IsFileExist(lock) {
		err = fmt.Errorf("lock file %s exists, another download is in progress, if it's not the case, manually remove the lock", lock)
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
			err = fmt.Errorf("failed to initialize HTTP client")
			return err
		}
		req, downloadErr := grab.NewRequest(path, tarballURL)
		if downloadErr != nil {
			downloadErr = fmt.Errorf("create grab request: %v", downloadErr)
			return downloadErr
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
					downloadErr = fmt.Errorf("download finished with error: %v", downloadErr)
					return downloadErr
				}
				if !verify_checksum() {
					err = fmt.Errorf("checksum verification failed")
					return err
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

	// find x-terminal-emulator, it should be available on most Linux distros, tested on Kali
	x_terminal_emulator, err := exec.LookPath("x-terminal-emulator")
	if err != nil {
		return fmt.Errorf("failed to find x-terminal-emulator: %v. your distribution is unsupported", err)
	}
	err = exec.Command(x_terminal_emulator, "-e", install_cmd).Run()
	if err != nil {
		return fmt.Errorf("failed to update emp3r0r: %v", err)
	}
	defer TmuxDeinitWindows()

	return nil
}
