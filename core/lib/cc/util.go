//go:build linux
// +build linux

package cc

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cavaliergopher/grab/v3"
	"github.com/google/uuid"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// DownloadFile download file using default http client
func DownloadFile(url, path string) (err error) {
	CliPrintDebug("Downloading '%s' to '%s'", url, path)
	_, err = grab.Get(path, url)
	return
}

// SendCmd send command to agent
func SendCmd(cmd, cmd_id string, a *emp3r0r_data.AgentSystemInfo) error {
	if a == nil {
		return errors.New("SendCmd: agent not found")
	}

	var cmdData emp3r0r_data.MsgTunData

	// add UUID to each command for tracking
	if cmd_id == "" {
		cmd_id = uuid.New().String()
	}
	cmdData.Payload = fmt.Sprintf("cmd%s%s%s%s",
		emp3r0r_data.MagicString, cmd,
		emp3r0r_data.MagicString, cmd_id)
	cmdData.Tag = a.Tag

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

func wait_for_cmd_response(cmd, cmd_id string, agent *emp3r0r_data.AgentSystemInfo) {
	ctrl, exists := Targets[agent]
	if !exists || agent == nil {
		CliPrintWarning("SendCmd: agent '%s' not connected", agent.Tag)
		return
	}
	now := time.Now()
	for ctrl.Ctx.Err() == nil {
		if _, exists := CmdResults[cmd_id]; exists {
			CmdResultsMutex.Lock()
			delete(CmdResults, cmd_id)
			CmdResultsMutex.Unlock()
			return
		}
		wait_time := time.Since(now)
		if wait_time > 1*time.Minute && !waitNeeded(cmd) {
			CliPrintError("Executing %s on %s: unresponsive for %v, removing agent from list",
				strconv.Quote(cmd),
				strconv.Quote(agent.Name),
				wait_time)
			ctrl.Cancel()
			return
		}
		util.TakeABlink()
	}
}

func waitNeeded(cmd string) bool {
	return strings.HasPrefix(cmd, "!") || strings.HasPrefix(cmd, "#get") || strings.HasPrefix(cmd, "put ")
}

// SendCmdToCurrentTarget send a command to currently selected agent
func SendCmdToCurrentTarget(cmd, cmd_id string) error {
	// target
	target := SelectCurrentTarget()
	if target == nil {
		return fmt.Errorf("You have to select a target first")
	}

	// send cmd
	return SendCmd(cmd, cmd_id, target)
}

// VimEdit launch local vim to edit files
func VimEdit(filepath string) (err error) {
	if os.Getenv("TMUX") == "" ||
		!util.IsCommandExist("tmux") ||
		!util.IsCommandExist("vim") {

		return errors.New("You need to run emp3r0r under tmux, and make sure vim is installed")
	}

	// split tmux window, remember pane number
	vimjob := fmt.Sprintf("tmux split-window 'echo -n $TMUX_PANE>%svim.pane;vim %s'", Temp, filepath)
	cmd := exec.Command("/bin/sh", "-c", vimjob)
	err = cmd.Run()
	if err != nil {
		return
	}

	// index of our tmux pane
	for {
		if _, err = os.Stat(Temp + "vim.pane"); os.IsNotExist(err) {
			time.Sleep(200 * time.Millisecond)
		} else {
			break
		}
	}

	// remove vim.pane eventually
	defer func() {
		err = os.Remove(Temp + "vim.pane")
		if err != nil {
			CliPrintWarning("%v", err)
		}
	}()

	paneBytes, e := os.ReadFile(Temp + "vim.pane")
	pane := string(paneBytes)
	if e != nil {
		return fmt.Errorf("cannot detect tmux pane number: %v", e)
	}

	// loop until vim exits
	for {
		time.Sleep(1 * time.Second)

		// check if our tmux pane exists, ie. the user hasn't done editing
		checkPaneCmd := exec.Command("tmux", "display-message", "-p", "-t", pane)
		out, err := checkPaneCmd.CombinedOutput()
		if err != nil {
			tmuxout := string(out)
			if strings.Contains(tmuxout, "can't find") {
				CliPrintSuccess("Vim has done editing")
				return nil
			}
			CliPrintError("%v", err)
			break
		}
	}

	return errors.New("don't know if vim has done editing")
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
		return fmt.Errorf("No available terminal emulator")
	}

	// works fine for gnome-terminal and xfce4-terminal
	job := fmt.Sprintf("%s -t '%s' -e '%s || read'", terminal, name, cmd)

	out, err := exec.Command("/bin/bash", "-c", job).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}

	return nil
}

// IsAgentExistByTag is agent already in target list?
func IsAgentExistByTag(tag string) bool {
	TargetsMutex.RLock()
	defer TargetsMutex.RUnlock()
	for a := range Targets {
		if a.Tag == tag {
			return true
		}
	}

	return false
}

// IsAgentExist is agent already in target list?
func IsAgentExist(t *emp3r0r_data.AgentSystemInfo) bool {
	TargetsMutex.RLock()
	defer TargetsMutex.RUnlock()
	for a := range Targets {
		if a.Tag == t.Tag {
			return true
		}
	}

	return false
}

// assignTargetIndex assign an index number to new agent
func assignTargetIndex() (index int) {
	TargetsMutex.RLock()
	defer TargetsMutex.RUnlock()

	// index is 0 for the first agent
	if len(Targets) == 0 {
		return 0
	}

	// loop thru agent list and get all index numbers
	index_list := make([]int, 0)
	for _, c := range Targets {
		index_list = append(index_list, c.Index)
	}

	// sort
	sort.Ints(index_list)

	// find available numbers
	available_indexes := make([]int, 0)
	for i := 0; i < len(index_list); i++ {
		if index_list[i] != i {
			available_indexes = append(available_indexes, i)
		}
	}
	if len(available_indexes) == 0 {
		return len(index_list)
	}

	// use the smallest available number
	return available_indexes[0]
}

// TermClear clear screen
func TermClear() {
	os.Stdout.WriteString(ClearTerm)
	err := CliBanner()
	if err != nil {
		CliPrintError("%v", err)
	}
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
			CliPrintDebug("Unlocking download: %s", f.Name())
			if err != nil {
				return fmt.Errorf("Remove %s: %v", f.Name(), err)
			}
		}
	}

	return nil
}
