package cc

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"strings"
	"sync"

	"github.com/fatih/color"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/olekukonko/tablewriter"
	"github.com/posener/h2conn"
)

var (
	// DebugLevel what kind fof logs do we want to see
	// 3 (DEBUG) -> 2 (INFO) -> 1 (WARN)
	DebugLevel = 2

	// IsAPIEnabled Indicate whether we are in headless mode
	IsAPIEnabled = false

	// Prefix /usr or /usr/local, can be set through $EMP3R0R_PREFIX
	Prefix = ""

	// EmpWorkSpace workspace directory of emp3r0r
	EmpWorkSpace = ""

	// EmpDataDir prefix/lib/emp3r0r
	EmpDataDir = ""

	// EmpBuildDir prefix/lib/emp3r0r/build
	EmpBuildDir = ""

	// FileGetDir where we save #get files
	FileGetDir = ""

	// EmpConfigFile emp3r0r.json
	EmpConfigFile = ""

	// Targets target list, with control (tun) interface
	Targets = make(map[*emp3r0r_data.AgentSystemInfo]*Control)
)

const (
	// Temp where we save temp files
	Temp = "/tmp/emp3r0r/"

	// WWWRoot host static files for agent
	WWWRoot = Temp + "www/"

	// UtilsArchive host utils.tar.bz2 for agent
	UtilsArchive = WWWRoot + "utils.tar.bz2"
)

// Control controller interface of a target
type Control struct {
	Index  int          // index of a connected agent
	Label  string       // custom label for an agent
	Conn   *h2conn.Conn // h2 connection of an agent
	Ctx    context.Context
	Cancel context.CancelFunc
}

// send JSON encoded target list to frontend
func headlessListTargets() (err error) {
	var targets []emp3r0r_data.AgentSystemInfo
	for target := range Targets {
		targets = append(targets, *target)
	}
	data, err := json.Marshal(targets)
	if err != nil {
		return
	}
	var resp APIResponse
	resp.Cmd = "ls_targets"
	resp.MsgData = data
	resp.MsgType = JSON
	resp.Alert = false
	respdata, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_, err = APIConn.Write([]byte(respdata))
	return
}

// ListTargets list currently connected agents
func ListTargets() {
	// return JSON data to APIConn in headless mode
	if IsAPIEnabled {
		if err := headlessListTargets(); err != nil {
			CliPrintError("ls_targets: %v", err)
		}
	}

	// build table
	tdata := [][]string{}
	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetHeader([]string{"Index", "Label", "Tag", "OS", "Process", "User", "IPs", "From"})
	table.SetBorder(true)
	table.SetRowLine(true)
	table.SetAutoWrapText(true)
	table.SetAutoFormatHeaders(true)
	table.SetReflowDuringAutoWrap(true)
	table.SetColWidth(20)

	// color
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiMagentaColor}, // index
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiMagentaColor}, // label
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgBlueColor},      // tag
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiWhiteColor},   // os
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiCyanColor},    // process
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiWhiteColor},   // user
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiBlueColor},    // from
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor})  // IPs

	table.SetColumnColor(
		tablewriter.Colors{tablewriter.FgHiMagentaColor}, // index
		tablewriter.Colors{tablewriter.FgHiMagentaColor}, // label
		tablewriter.Colors{tablewriter.FgBlueColor},      // tag
		tablewriter.Colors{tablewriter.FgHiWhiteColor},   // os
		tablewriter.Colors{tablewriter.FgHiCyanColor},    // process
		tablewriter.Colors{tablewriter.FgHiWhiteColor},   // user
		tablewriter.Colors{tablewriter.FgHiBlueColor},    // from
		tablewriter.Colors{tablewriter.FgYellowColor})    // IPs

	// fill table
	var tail []string
	for target, control := range Targets {
		// label
		if control.Label == "" {
			control.Label = "nolabel"
		}
		index := fmt.Sprintf("%d", control.Index)
		label := control.Label

		// agent process info
		agentProc := *target.Process
		procInfo := fmt.Sprintf("%s (%d)\n<- %s (%d)",
			agentProc.Cmdline, agentProc.PID, agentProc.Parent, agentProc.PPID)

		// info map
		ips := strings.Join(target.IPs, ",\n")
		infoMap := map[string]string{
			"OS":      util.SplitLongLine(target.OS, 20),
			"Process": util.SplitLongLine(procInfo, 20),
			"User":    util.SplitLongLine(target.User, 20),
			"From":    fmt.Sprintf("%s\nvia %s", target.From, target.Transport),
			"IPs":     ips,
		}

		var row = []string{index, label, util.SplitLongLine(target.Tag, 15),
			infoMap["OS"], infoMap["Process"], infoMap["User"], infoMap["IPs"], infoMap["From"]}

		// is this agent currently selected?
		if CurrentTarget != nil {
			if CurrentTarget.Tag == target.Tag {
				index = color.New(color.FgHiGreen, color.Bold).Sprintf("%d", control.Index)
				row = []string{index, label, util.SplitLongLine(target.Tag, 15),
					infoMap["OS"], infoMap["Process"], infoMap["User"], infoMap["IPs"], infoMap["From"]}

				// put this row at bottom, so it's always visible
				tail = row
				continue
			}
		}

		tdata = append(tdata, row)
	}
	if tail != nil {
		tdata = append(tdata, tail)
	}
	// rendor table
	table.AppendBulk(tdata)
	table.Render()

	if AgentListPane == nil {
		CliPrintError("AgentListPane doesn't exist")
		return
	}
	AgentListPane.Printf(true, "\n\033[0m%s\n\n", tableString.String())
}

func GetTargetDetails(target *emp3r0r_data.AgentSystemInfo) {
	// exists?
	if !IsAgentExist(target) {
		CliPrintError("Target does not exist")
		return
	}
	control := Targets[target]

	// build table
	tdata := [][]string{}
	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetHeader([]string{"Property", "Value"})
	table.SetBorder(true)
	table.SetRowLine(true)
	table.SetAutoWrapText(true)
	table.SetColWidth(20)

	// color
	table.SetHeaderColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiCyanColor})

	hasInternet := color.HiRedString("NO")
	if target.HasInternet {
		hasInternet = color.HiGreenString("YES")
	}

	arpTab := strings.Join(target.ARP, ",\n")
	ips := strings.Join(target.IPs, ",\n")
	userInfo := color.HiRedString(target.User)
	if target.HasRoot {
		userInfo = color.HiGreenString(target.User)
	}
	userInfo = util.SplitLongLine(userInfo, 20)
	cpuinfo := color.HiMagentaString(target.CPU)
	gpuinfo := color.HiMagentaString(target.GPU)
	gpuinfo = util.SplitLongLine(gpuinfo, 20)

	// agent process info
	agentProc := *target.Process
	procInfo := fmt.Sprintf("%s (%d)\n<- %s (%d)",
		agentProc.Cmdline, agentProc.PID, agentProc.Parent, agentProc.PPID)
	procInfo = util.SplitLongLine(procInfo, 20)

	// info map
	infoMap := map[string]string{
		"Version":   color.HiWhiteString(target.Version),
		"Hostname":  util.SplitLongLine(color.HiCyanString(target.Hostname), 20),
		"Process":   util.SplitLongLine(color.HiMagentaString(procInfo), 20),
		"User":      userInfo,
		"Internet":  hasInternet,
		"CPU":       cpuinfo,
		"GPU":       gpuinfo,
		"MEM":       target.Mem,
		"Hardware":  util.SplitLongLine(color.HiCyanString(target.Hardware), 20),
		"Container": target.Container,
		"OS":        util.SplitLongLine(color.HiWhiteString(target.OS), 20),
		"Kernel":    util.SplitLongLine(color.HiBlueString(target.Kernel)+", "+color.HiWhiteString(target.Arch), 20),
		"From":      util.SplitLongLine(color.HiYellowString(target.From)+fmt.Sprintf(" - %s", color.HiGreenString(target.Transport)), 20),
		"IPs":       color.BlueString(ips),
		"ARP":       color.HiWhiteString(arpTab),
	}

	// print
	if control.Label == "" {
		control.Label = "nolabel"
	}

	indexRow := []string{"Index", color.HiMagentaString("%d", control.Index)}
	labelRow := []string{"Label", color.HiCyanString(control.Label)}
	tagRow := []string{"Tag", color.CyanString(util.SplitLongLine(target.Tag, 20))}
	tdata = append(tdata, indexRow)
	tdata = append(tdata, labelRow)
	tdata = append(tdata, tagRow)
	for key, val := range infoMap {
		tdata = append(tdata, []string{key, val})
	}

	// rendor table
	table.AppendBulk(tdata)
	table.Render()
	num_of_lines := len(strings.Split(tableString.String(), "\n"))
	num_of_columns := len(strings.Split(tableString.String(), "\n")[0])
	if AgentInfoPane == nil {
		CliPrintError("AgentInfoPane doesn't exist")
		return
	}
	AgentInfoPane.ResizePane("y", num_of_lines)
	AgentInfoPane.ResizePane("x", num_of_columns)
	AgentInfoPane.Printf(true, "\n\033[0m%s\n\n", tableString.String())

	// Update Agent list
	ListTargets()
}

// GetTargetFromIndex find target from Targets via control index, return nil if not found
func GetTargetFromIndex(index int) (target *emp3r0r_data.AgentSystemInfo) {
	for t, ctl := range Targets {
		if ctl.Index == index {
			target = t
			break
		}
	}
	return
}

// GetTargetFromTag find target from Targets via tag, return nil if not found
func GetTargetFromTag(tag string) (target *emp3r0r_data.AgentSystemInfo) {
	for t := range Targets {
		if t.Tag == tag {
			target = t
			break
		}
	}
	return
}

// GetTargetFromH2Conn find target from Targets via HTTP2 connection ID, return nil if not found
func GetTargetFromH2Conn(conn *h2conn.Conn) (target *emp3r0r_data.AgentSystemInfo) {
	for t, ctrl := range Targets {
		if conn == ctrl.Conn {
			target = t
			break
		}
	}
	return
}

type LabeledAgent struct {
	Tag   string `json:"tag"`
	Label string `json:"label"`
}

const AgentsJSON = "agents.json"

// save custom labels
func labelAgents() {
	var (
		labeledAgents []LabeledAgent
		old           []LabeledAgent
	)
	// what if emp3r0r_data.json already have some records
	if util.IsFileExist(AgentsJSON) {
		data, err := ioutil.ReadFile(AgentsJSON)
		if err != nil {
			CliPrintWarning("Reading labeled agents: %v", err)
		}
		err = json.Unmarshal(data, &old)
		if err != nil {
			CliPrintWarning("Reading labeled agents: %v", err)
		}
	}

	// save current labels
outter:
	for t, c := range Targets {
		if c.Label == "" {
			continue
		}
		labeled := &LabeledAgent{}
		labeled.Label = c.Label
		labeled.Tag = t.Tag

		// exists in json file?
		for i, l := range old {
			if l.Tag == labeled.Tag {
				l.Label = labeled.Label // update label
				old[i] = l
				continue outter
			}
		}

		// if new, write it
		labeledAgents = append(labeledAgents, *labeled)
	}
	labeledAgents = append(labeledAgents, old...) // append old labels

	if len(labeledAgents) == 0 {
		return
	}
	data, err := json.Marshal(labeledAgents)
	if err != nil {
		CliPrintWarning("Saving labeled agents: %v", err)
		return
	}

	// write file
	err = ioutil.WriteFile(AgentsJSON, data, 0600)
	if err != nil {
		CliPrintWarning("Saving labeled agents: %v", err)
	}
}

// SetAgentLabel if an agent is already labeled, we can set its label in later sessions
func SetAgentLabel(a *emp3r0r_data.AgentSystemInfo, mutex *sync.Mutex) (label string) {
	data, err := ioutil.ReadFile(AgentsJSON)
	if err != nil {
		CliPrintWarning("SetAgentLabel: %v", err)
		return
	}
	var labeledAgents []LabeledAgent
	err = json.Unmarshal(data, &labeledAgents)
	if err != nil {
		CliPrintWarning("SetAgentLabel: %v", err)
		return
	}

	for _, labeled := range labeledAgents {
		if a.Tag == labeled.Tag {
			mutex.Lock()
			defer mutex.Unlock()
			if Targets[a] != nil {
				Targets[a].Label = labeled.Label
			}
			label = labeled.Label
			return
		}
	}

	return
}

// ListModules list all available modules
func ListModules() {
	CliPrettyPrint("Module Name", "Help", &emp3r0r_data.ModuleComments)
}

// Send2Agent send MsgTunData to agent
func Send2Agent(data *emp3r0r_data.MsgTunData, agent *emp3r0r_data.AgentSystemInfo) (err error) {
	ctrl := Targets[agent]
	if ctrl == nil {
		return fmt.Errorf("Send2Agent (%s): Target is not connected", data.Payload)
	}
	if ctrl.Conn == nil {
		return fmt.Errorf("Send2Agent (%s): Target is not connected", data.Payload)
	}
	out := json.NewEncoder(ctrl.Conn)

	err = out.Encode(data)
	return
}

// DirSetup set workspace, module directories, etc
func DirSetup() (err error) {
	// prefix
	Prefix = os.Getenv("EMP3R0R_PREFIX")
	if Prefix == "" {
		Prefix = "/usr/local"
	}
	// eg. /usr/local/lib/emp3r0r
	EmpDataDir = Prefix + "/lib/emp3r0r"
	EmpBuildDir = EmpDataDir + "/build"
	CAT = EmpDataDir + "/emp3r0r-cat"
	if !util.IsFileExist(EmpDataDir) {
		return fmt.Errorf("emp3r0r is not installed correctly: %s not found", EmpDataDir)
	}
	if !util.IsFileExist(CAT) {
		return fmt.Errorf("emp3r0r is not installed correctly: %s not found", CAT)
	}

	// set workspace to ~/.emp3r0r
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("Get current user: %v", err)
	}
	EmpWorkSpace = fmt.Sprintf("%s/.emp3r0r", u.HomeDir)
	if !util.IsFileExist(EmpWorkSpace) {
		err = os.MkdirAll(EmpWorkSpace, 0700)
		if err != nil {
			return fmt.Errorf("mkdir %s: %v", EmpWorkSpace, err)
		}
	}
	FileGetDir = EmpWorkSpace + "/file-get/"
	EmpConfigFile = EmpWorkSpace + "/emp3r0r.json"

	// cd to workspace
	err = os.Chdir(EmpWorkSpace)
	if err != nil {
		return fmt.Errorf("cd to workspace %s: %v", EmpWorkSpace, err)
	}

	// Module directories
	ModuleDirs = []string{EmpDataDir + "/modules", EmpWorkSpace + "/modules"}

	return
}
