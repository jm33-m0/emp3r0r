//go:build linux
// +build linux

package cc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/fatih/color"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/olekukonko/tablewriter"
	"github.com/posener/h2conn"
	"github.com/spf13/cobra"
)

var (
	// DebugLevel what kind fof logs do we want to see
	// 3 (DEBUG) -> 2 (INFO) -> 1 (WARN)
	DebugLevel = 2

	// TmuxPersistence enable debug (-debug)
	TmuxPersistence = false

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
	Targets      = make(map[*emp3r0r_def.Emp3r0rAgent]*Control)
	TargetsMutex = sync.RWMutex{}

	// certs
	CACrtFile     string
	CAKeyFile     string
	ServerCrtFile string
	ServerKeyFile string
)

const (
	// Temp where we save temp files
	Temp = "/tmp/emp3r0r/"

	// WWWRoot host static files for agent
	WWWRoot = Temp + "www/"

	// UtilsArchive host utils.tar.xz for agent
	UtilsArchive = WWWRoot + "utils.tar.xz"
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
	TargetsMutex.RLock()
	defer TargetsMutex.RUnlock()
	var targets []emp3r0r_def.Emp3r0rAgent
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
	TargetsMutex.RLock()
	defer TargetsMutex.RUnlock()
	// return JSON data to APIConn in headless mode
	if IsAPIEnabled {
		if listErr := headlessListTargets(); listErr != nil {
			LogError("ls_targets: %v", listErr)
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

		row := []string{
			index, label, util.SplitLongLine(target.Tag, 15),
			infoMap["OS"], infoMap["Process"], infoMap["User"], infoMap["IPs"], infoMap["From"],
		}

		// is this agent currently selected?
		if CurrentTarget != nil {
			if CurrentTarget.Tag == target.Tag {
				index = color.New(color.FgHiGreen, color.Bold).Sprintf("%d", control.Index)
				row = []string{
					index, label, util.SplitLongLine(target.Tag, 15),
					infoMap["OS"], infoMap["Process"], infoMap["User"], infoMap["IPs"], infoMap["From"],
				}

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
		LogError("AgentListPane doesn't exist")
		return
	}
	AgentListPane.Printf(true, "\n\033[0m%s\n\n", tableString.String())
}

// Update agent list, then switch to its tmux window
func ls_targets(cmd *cobra.Command, args []string) {
	ListTargets()
	TmuxSwitchWindow(AgentListPane.WindowID)
}

// GetTargetFromIndex find target from Targets via control index, return nil if not found
func GetTargetFromIndex(index int) (target *emp3r0r_def.Emp3r0rAgent) {
	TargetsMutex.RLock()
	defer TargetsMutex.RUnlock()
	for t, ctl := range Targets {
		if ctl.Index == index {
			target = t
			break
		}
	}
	return
}

// GetTargetFromTag find target from Targets via tag, return nil if not found
func GetTargetFromTag(tag string) (target *emp3r0r_def.Emp3r0rAgent) {
	TargetsMutex.RLock()
	defer TargetsMutex.RUnlock()
	for t := range Targets {
		if t.Tag == tag {
			target = t
			break
		}
	}
	return
}

// GetTargetFromH2Conn find target from Targets via HTTP2 connection ID, return nil if not found
func GetTargetFromH2Conn(conn *h2conn.Conn) (target *emp3r0r_def.Emp3r0rAgent) {
	TargetsMutex.RLock()
	defer TargetsMutex.RUnlock()
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
	// what if emp3r0r_def.json already have some records
	if util.IsExist(AgentsJSON) {
		data, readErr := os.ReadFile(AgentsJSON)
		if readErr != nil {
			LogWarning("Reading labeled agents: %v", readErr)
		}
		readErr = json.Unmarshal(data, &old)
		if readErr != nil {
			LogWarning("Reading labeled agents: %v", readErr)
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
	data, marshalErr := json.Marshal(labeledAgents)
	if marshalErr != nil {
		LogWarning("Saving labeled agents: %v", marshalErr)
		return
	}

	// write file
	marshalErr = os.WriteFile(AgentsJSON, data, 0o600)
	if marshalErr != nil {
		LogWarning("Saving labeled agents: %v", marshalErr)
	}
}

// SetAgentLabel if an agent is already labeled, we can set its label in later sessions
func SetAgentLabel(a *emp3r0r_def.Emp3r0rAgent) (label string) {
	TargetsMutex.RLock()
	defer TargetsMutex.RUnlock()
	data, err := os.ReadFile(AgentsJSON)
	if err != nil {
		LogWarning("SetAgentLabel: %v", err)
		return
	}
	var labeledAgents []LabeledAgent
	err = json.Unmarshal(data, &labeledAgents)
	if err != nil {
		LogWarning("SetAgentLabel: %v", err)
		return
	}

	for _, labeled := range labeledAgents {
		if a.Tag == labeled.Tag {
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
	mod_comment_map := make(map[string]string)
	for mod_name, mod := range emp3r0r_def.Modules {
		mod_comment_map[mod_name] = mod.Comment
	}
	CliPrettyPrint("Module Name", "Help", &mod_comment_map)
}

// Send2Agent send MsgTunData to agent
func Send2Agent(data *emp3r0r_def.MsgTunData, agent *emp3r0r_def.Emp3r0rAgent) (err error) {
	TargetsMutex.RLock()
	defer TargetsMutex.RUnlock()
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

// InitC2 set workspace, module directories, etc
func InitC2() (err error) {
	// prefix
	Prefix = os.Getenv("EMP3R0R_PREFIX")
	if Prefix == "" {
		Prefix = "/usr/local"
	}
	// eg. /usr/local/lib/emp3r0r
	EmpDataDir = Prefix + "/lib/emp3r0r"
	EmpBuildDir = EmpDataDir + "/build"
	CAT = EmpDataDir + "/emp3r0r-cat"

	if !util.IsExist(EmpDataDir) {
		return fmt.Errorf("emp3r0r is not installed correctly: %s not found", EmpDataDir)
	}
	if !util.IsExist(CAT) {
		return fmt.Errorf("emp3r0r is not installed correctly: %s not found", CAT)
	}

	// set workspace to ~/.emp3r0r
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("get current user: %v", err)
	}
	EmpWorkSpace = u.HomeDir + "/.emp3r0r"
	FileGetDir = EmpWorkSpace + "/file-get/"
	EmpConfigFile = EmpWorkSpace + "/emp3r0r.json"
	if !util.IsDirExist(EmpWorkSpace) {
		err = os.MkdirAll(FileGetDir, 0o700)
		if err != nil {
			return fmt.Errorf("mkdir %s: %v", EmpWorkSpace, err)
		}
	}

	// prefixes for stubs
	emp3r0r_def.Stub_Linux = EmpWorkSpace + "/stub"
	emp3r0r_def.Stub_Windows = EmpWorkSpace + "/stub-win"

	// copy stub binaries to ~/.emp3r0r
	stubFiles, err := filepath.Glob(fmt.Sprintf("%s/stub*", EmpBuildDir))
	if err != nil {
		LogWarning("Agent stubs: %v", err)
	}
	for _, stubFile := range stubFiles {
		copyErr := util.Copy(stubFile, EmpWorkSpace)
		if copyErr != nil {
			LogWarning("Agent stubs: %v", copyErr)
		}
	}

	// cd to workspace
	err = os.Chdir(EmpWorkSpace)
	if err != nil {
		return fmt.Errorf("cd to workspace %s: %v", EmpWorkSpace, err)
	}

	// Module directories
	ModuleDirs = []string{EmpDataDir + "/modules", EmpWorkSpace + "/modules"}

	// cert files
	CACrtFile = EmpWorkSpace + "/ca-cert.pem"
	CAKeyFile = EmpWorkSpace + "/ca-key.pem"
	ServerCrtFile = EmpWorkSpace + "/emp3r0r-cert.pem"
	ServerKeyFile = EmpWorkSpace + "/emp3r0r-key.pem"

	// log files
	AgentOuputLogFile = fmt.Sprintf("%s/agent_output.log", EmpWorkSpace)

	return
}

func setActiveTarget(cmd *cobra.Command, args []string) {
	target, err := cmd.Flags().GetString("id")
	if err != nil {
		LogError("set target: %v", err)
		return
	}
	var target_to_set *emp3r0r_def.Emp3r0rAgent

	// select by tag or index
	target_to_set = GetTargetFromTag(target)
	if target_to_set == nil {
		index, e := strconv.Atoi(target)
		if e == nil {
			target_to_set = GetTargetFromIndex(index)
		}
	}

	select_agent := func(a *emp3r0r_def.Emp3r0rAgent) {
		CurrentTarget = a
		LogSuccess("Now targeting %s", CurrentTarget.Tag)
		LogMsg("Run `file_manager` to open a SFTP session")
		autoCompleteAgentExes(target_to_set)
	}

	if target_to_set == nil {
		// if still nothing
		LogError("Target does not exist, no target has been selected")
		return

	} else {
		// lets start the bash shell
		go select_agent(target_to_set)
	}
}
