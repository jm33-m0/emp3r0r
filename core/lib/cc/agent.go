//go:build linux
// +build linux

package cc

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/olekukonko/tablewriter"
)

// CmdResults receive response from agent and cache them
var CmdResults = make(map[string]string)

// mutex
var CmdResultsMutex = &sync.Mutex{}

// processAgentData deal with data from agent side
func processAgentData(data *emp3r0r_def.MsgTunData) {
	var err error
	TargetsMutex.RLock()
	defer TargetsMutex.RUnlock()

	target := GetTargetFromTag(data.Tag)
	contrlIf := Targets[target]
	if target == nil || contrlIf == nil {
		LogError("Target %s cannot be found, however, it left a message saying:\n%v",
			data.Tag, data.CmdSlice)
		return
	}

	// cmd output from agent
	cmd := data.CmdSlice[0]
	is_builtin_cmd := strings.HasPrefix(cmd, "!")
	cmd_slice := data.CmdSlice
	out := data.Response
	cmd_id := data.CmdID
	// cache this cmd response
	CmdResultsMutex.Lock()
	CmdResults[cmd_id] = out
	CmdResultsMutex.Unlock()

	switch cmd_slice[0] {
	// screenshot command
	case "screenshot":
		go func() {
			err = processScreenshot(out, target)
			if err != nil {
				LogError("%v", err)
			}
		}()

		// ps command
	case "ps":
		var procs []util.ProcEntry
		err = json.Unmarshal([]byte(out), &procs)
		if err != nil {
			LogDebug("ps: %v", err)
			LogError("ps: %s", err, out)
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
		table.SetColWidth(20)

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
			pname := util.SplitLongLine(p.Name, 20)
			tdata = append(tdata, []string{pname, strconv.Itoa(p.PID), strconv.Itoa(p.PPID), p.Token})
		}
		table.AppendBulk(tdata)
		table.Render()
		out = tableString.String()

		// resize pane since table might mess up
		x := len(strings.Split(out, "\n")[0])
		FitPanes(x)

		// ls command
	case "ls":
		var dents []util.Dentry
		err = json.Unmarshal([]byte(out), &dents)
		if err != nil {
			LogDebug("ls: %v", err)
			LogError("ls: %s", out)
			return
		}

		// build table
		tdata := [][]string{}
		tableString := &strings.Builder{}
		table := tablewriter.NewWriter(tableString)
		table.SetHeader([]string{"Name", "Type", "Size", "Time", "Permission"})
		table.SetRowLine(true)
		table.SetBorder(true)
		table.SetColWidth(20)
		table.SetAutoWrapText(true)

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
			dname := util.SplitLongLine(d.Name, 20)
			tdata = append(tdata, []string{dname, d.Ftype, d.Size, d.Date, d.Permission})
		}

		// print table
		table.AppendBulk(tdata)
		table.Render()
		out = tableString.String()

		// resize pane since table might mess up
		x := len(strings.Split(out, "\n")[0])
		FitPanes(x)
	}

	// Command output
	no_need_to_show := strings.HasPrefix(cmd, emp3r0r_def.C2CmdPortFwd) ||
		strings.HasPrefix(cmd, emp3r0r_def.C2CmdSSHD) || strings.HasPrefix(cmd, emp3r0r_def.C2CmdListDir)
	if Logger.Level < 3 {
		// ignore some cmds
		if no_need_to_show {
			return
		}
	}
	agent_output := fmt.Sprintf("\n[%s] %s:\n%s\n\n",
		color.CyanString("%d", contrlIf.Index),
		color.HiMagentaString("%s", cmd),
		color.HiWhiteString(out))
	LogMsg(agent_output)

	// time spent on this cmd
	start_time, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", CmdTime[cmd_id])
	if err != nil {
		LogWarning("Parsing timestamp '%s': %v", CmdTime[cmd_id], err)
	} else {
		time_spent := time.Since(start_time)
		if is_builtin_cmd {
			LogDebug("Command %s took %s", strconv.Quote(cmd), time_spent)
		} else {
			LogMsg("Command %s took %s", strconv.Quote(cmd), time_spent)
		}
	}
}
