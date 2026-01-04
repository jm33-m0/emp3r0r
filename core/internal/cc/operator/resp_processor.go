package operator

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// processAgentData deal with data from agent side
func processAgentData(data *def.MsgTunData) {
	var err error

	// what if this message is a broadcast from C2
	switch data.Tag {
	case logging.SUCCESS:
		logging.Successf("%s", data.Response)
		refreshAgentList() // it might be a new agent
		return
	case logging.ERROR:
		logging.Errorf("%s", data.Response)
		refreshAgentList() // it might be an agent disconnecting
		return
	case logging.WARN:
		logging.Warningf("%s", data.Response)
		return
	case logging.INFO:
		logging.Infof("%s", data.Response)
		return
	}

	target := agents.GetAgentByTag(data.Tag)
	if target == nil {
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
	live.CmdResults.Store(cmd_id, string(out))

	switch cmd_slice[0] {
	// screenshot command
	case "screenshot":
		go func() {
			err = modules.ProcessScreenshot(string(out), target)
			if err != nil {
				logging.Errorf("%v", err)
			}
		}()

		// ps command
	case "ps":
		var procs []util.ProcEntry
		err = cbor.Unmarshal([]byte(out), &procs)
		if err != nil {
			logging.Debugf("ps: %v", err)
			logging.Errorf("ps: %v", err)
			return
		}

		// Build table data
		tdata := [][]string{}
		for _, p := range procs {
			pname := util.SplitLongLine(p.Name, 20)
			tdata = append(tdata, []string{pname, strconv.Itoa(p.PID), strconv.Itoa(p.PPID), p.Token})
		}

		// Use BuildTable instead of manual tablewriter creation
		out = []byte(cli.BuildTable([]string{"Name", "PID", "PPID", "User"}, tdata))

		// Use AdaptiveTable instead of FitPanes
		cli.AdaptiveTable(string(out))

		// ls command
	case "ls":
		var dents []util.Dentry
		err = cbor.Unmarshal([]byte(out), &dents)
		if err != nil {
			logging.Debugf("ls: %v", err)
			logging.Errorf("ls: %v", err)
			return
		}

		// Build table data
		tdata := [][]string{}
		for _, d := range dents {
			dname := util.SplitLongLine(d.Name, 20)
			tdata = append(tdata, []string{dname, d.Ftype, d.Size, d.Date, d.Permission})
		}

		// Use BuildTable instead of manual tablewriter creation
		out = []byte(cli.BuildTable([]string{"Name", "Type", "Size", "Time", "Permission"}, tdata))

		// Use AdaptiveTable instead of FitPanes
		cli.AdaptiveTable(string(out))
	}

	// Command output
	no_need_to_show := strings.HasPrefix(cmd, def.C2CmdPortFwd) ||
		strings.HasPrefix(cmd, def.C2CmdSSHD) || strings.HasPrefix(cmd, def.C2CmdListDir)
	if logging.Level < 3 {
		// ignore some cmds
		if no_need_to_show {
			return
		}
	}
	agent_output := fmt.Sprintf("\n[%s] %s:\n%s\n\n",
		color.CyanString("%s", target.Name),
		color.HiMagentaString("%s", cmd),
		color.HiWhiteString(string(out)))
	logging.Printf(agent_output)

	// time spent on this cmd
	cmdtime, ok := live.CmdTime[cmd_id]
	if !ok {
		logging.Warningf("No start time found for command %s", cmd)
		return
	}
	start_time, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", cmdtime)
	if err != nil {
		logging.Warningf("Parsing timestamp '%s': %v", live.CmdTime[cmd_id], err)
	} else {
		time_spent := time.Since(start_time)
		if is_builtin_cmd {
			logging.Debugf("Command %s took %s", strconv.Quote(cmd), time_spent)
		} else {
			logging.Printf("Command %s took %s", strconv.Quote(cmd), time_spent)
		}
	}
}
