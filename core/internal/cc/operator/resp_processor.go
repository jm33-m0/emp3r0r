package operator

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// CommandHandler handles specific command responses from agents
type CommandHandler func(out []byte, target *def.Emp3r0rAgent) string

// CommandHandlers maps command names to their handlers
var CommandHandlers = map[string]CommandHandler{
	"ps":      handlePS,
	"ls":      handleLS,
	"stat":    handleStat,
	"sysinfo": handleSysInfo,
}

func handleSysInfo(out []byte, target *def.Emp3r0rAgent) string {
	var info def.Emp3r0rAgent
	err := cbor.Unmarshal(out, &info)
	if err != nil {
		logging.Debugf("sysinfo: %v", err)
		logging.Errorf("sysinfo: %v", err)
		return ""
	}

	// Build table headers and row
	var headers []string
	var row []string

	addIfNotEmpty := func(name, value string) {
		if value != "" && value != "[]" && value != "0" {
			headers = append(headers, name)
			row = append(row, value)
		}
	}

	addIfNotEmpty("Hostname", info.Hostname)
	addIfNotEmpty("Uptime", info.Uptime)
	addIfNotEmpty("OS", info.OS)
	addIfNotEmpty("Kernel", info.Kernel)
	addIfNotEmpty("Arch", info.Arch)
	addIfNotEmpty("CPU", info.CPU)
	addIfNotEmpty("Mem", info.Mem)
	addIfNotEmpty("User", info.User)
	addIfNotEmpty("Groups", info.Groups)
	addIfNotEmpty("IPs", fmt.Sprintf("%v", info.IPs))
	if info.Container != "" && info.Container != "N/A" {
		addIfNotEmpty("Container", info.Container)
	}
	// addIfNotEmpty("ARP", fmt.Sprintf("%v", info.ARP)) // ARP might be too long for horizontal table
	if info.Process != nil {
		addIfNotEmpty("Agent PID", strconv.Itoa(info.Process.PID))
	}
	addIfNotEmpty("CWD", info.CWD)
	addIfNotEmpty("Transport", info.Transport)

	// Use BuildTable with horizontal layout
	outTable := cli.BuildTable(headers, [][]string{row})

	// Use AdaptiveTable
	cli.AdaptiveTable(outTable)

	return outTable
}

func handlePS(out []byte, target *def.Emp3r0rAgent) string {
	var procs []util.ProcEntry
	err := cbor.Unmarshal(out, &procs)
	if err != nil {
		logging.Debugf("ps: %v", err)
		logging.Errorf("ps: %v", err)
		return ""
	}

	// Build table data
	tdata := [][]string{}
	for _, p := range procs {
		pname := util.SplitLongLine(p.Name, 20)
		tdata = append(tdata, []string{pname, strconv.Itoa(p.PID), strconv.Itoa(p.PPID), p.Token})
	}

	// Use BuildTable instead of manual tablewriter creation
	outTable := cli.BuildTable([]string{"Name", "PID", "PPID", "User"}, tdata)

	// Use AdaptiveTable instead of FitPanes
	cli.AdaptiveTable(outTable)

	return outTable
}

func handleLS(out []byte, target *def.Emp3r0rAgent) string {
	var dents []util.Dentry
	err := cbor.Unmarshal(out, &dents)
	if err != nil {
		logging.Debugf("ls: %v", err)
		logging.Errorf("ls: %v", err)
		return ""
	}

	// Build table data
	tdata := [][]string{}
	for _, d := range dents {
		dname := util.SplitLongLine(d.Name, 20)
		tdata = append(tdata, []string{dname, d.Ftype, d.Size, d.Date, d.Permission})
	}

	// Use BuildTable instead of manual tablewriter creation
	outTable := cli.BuildTable([]string{"Name", "Type", "Size", "Time", "Permission"}, tdata)

	// Use AdaptiveTable instead of FitPanes
	cli.AdaptiveTable(outTable)

	return outTable
}

func handleStat(out []byte, target *def.Emp3r0rAgent) string {
	var stat util.FileStat
	err := cbor.Unmarshal(out, &stat)
	if err != nil {
		logging.Debugf("stat: %v", err)
		logging.Errorf("stat: %v", err)
		return ""
	}

	// Build table headers and row
	headers := []string{"Name", "Size", "Perm", "Checksum"}
	row := []string{
		stat.Name,
		fmt.Sprintf("%d", stat.Size),
		stat.Permission,
		stat.Checksum,
	}

	// Use BuildTable with horizontal layout
	outTable := cli.BuildTable(headers, [][]string{row})

	// Use AdaptiveTable
	cli.AdaptiveTable(outTable)

	return outTable
}

// processAgentData deal with data from agent side
func processAgentData(data *def.MsgTunData) {
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

	var target *def.Emp3r0rAgent
	if data.AgentUUID != "" {
		target = agents.GetAgentByUUID(data.AgentUUID)
	}
	if target == nil {
		target = agents.GetAgentByTag(data.Tag)
	}

	if target == nil {
		logging.Errorf("Target %s (%s) cannot be found, however, it left a message saying:\n%v",
			data.Tag, data.AgentUUID, data.CmdSlice)
		return
	}

	// Update last seen
	target.LastSeen = time.Now()

	// cmd output from agent
	cmd := data.CmdSlice[0]
	is_builtin_cmd := strings.HasPrefix(cmd, "!")
	cmd_slice := data.CmdSlice
	out := data.Response
	cmd_id := data.CmdID
	// cache this cmd response
	live.CmdResults.Store(cmd_id, string(out))

	// Handle specific commands that need special processing
	lookup_cmd := strings.TrimPrefix(cmd_slice[0], "!")
	if handler, ok := CommandHandlers[lookup_cmd]; ok {
		out = []byte(handler(out, target))
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

	// Strip ANSI escape codes using helper
	stripped := util.StripANSI(string(out))
	agent_output := fmt.Sprintf("\n[%s] %s:\n%s\n",
		color.CyanString("%s", target.Name),
		color.HiMagentaString("%s", cmd),
		color.HiWhiteString(stripped))
	// time spent on this cmd
	cmdtime, ok := live.CmdTime[cmd_id]
	if !ok {
		logging.Warningf("No start time found for command %s", cmd)
		logging.Printf(agent_output)
		return
	}
	start_time, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", cmdtime)
	if err != nil {
		logging.Warningf("Parsing timestamp '%s': %v", live.CmdTime[cmd_id], err)
		logging.Printf(agent_output)
	} else {
		time_spent := time.Since(start_time)
		target.LastSeenRTT = time_spent
		target.LastSeen = time.Now()
		if is_builtin_cmd {
			logging.Debugf("Command %s took %s", strconv.Quote(cmd), time_spent)
			logging.Printf(agent_output)
		} else {
			// Append latency to output
			agent_output = fmt.Sprintf("%s\n%s", agent_output, color.HiCyanString("Latency: %s\n\n", time_spent))
			logging.Printf(agent_output)
		}
	}
}
