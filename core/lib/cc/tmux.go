package cc

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// Emp3r0rPane a tmux window/pane that makes emp3r0r CC's interface
type Emp3r0rPane struct {
	ID  string   // tmux pane unique ID, needs to be converted to index when using select-pane
	PID int      // PID of the process running in tmux pane
	FD  *os.File // write to this file to get your message displayed on this pane
}

var (
	// Displays system info of selected agent
	AgentInfoWindow *Emp3r0rPane

	// Displays agent output, separated from logs
	AgentOutputWindow *Emp3r0rPane

	// Displays bash shell for selected agent
	AgentShellWindow *Emp3r0rPane

	// Put all windows in this map
	TmuxWindows = make(map[string]*Emp3r0rPane)
)

// TmuxPrintf like printf, but prints to a tmux pane/window
// id: pane unique id
func TmuxPrintf(clear bool, id string, format string, a ...interface{}) {
	if clear {
		err := TmuxClearPane(id)
		if err != nil {
			CliPrintWarning("Clear pane: %v", err)
		}
	}
	msg := fmt.Sprintf(format, a...)

	idx := TmuxPaneID2Index(id)
	if idx < 0 {
		CliPrintWarning("Cannot find tmux window "+id+
			", printing to main window instead.\n\n"+
			format, a...)
	}

	// find target pane and print msg
	for pane_id, window := range TmuxWindows {
		if pane_id != id {
			continue
		}
		_, err = window.FD.WriteString(msg)
		if err != nil {
			CliPrintWarning("Cannot print on tmux window "+id+
				", printing to main window instead.\n\n"+
				format, a...)
		}
		break
	}
}

func TmuxClearPane(id string) (err error) {
	idx := TmuxPaneID2Index(id)
	job := fmt.Sprintf("tmux clear-history -t %d", idx)
	out, err := exec.Command("/bin/sh", "-c", job).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("exec tmux clear pane: %s\n%v", out, err)
		return
	}
	return
}

func TmuxKillPane(id string) (err error) {
	idx := TmuxPaneID2Index(id)
	job := fmt.Sprintf("tmux kill-pane -t %d", idx)
	out, err := exec.Command("/bin/sh", "-c", job).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("exec tmux kill-pane: %s\n%v", out, err)
		return
	}
	return
}

// TmuxDeinitWindows close previously opened tmux windows
func TmuxDeinitWindows() {
	for id := range TmuxWindows {
		err = TmuxKillPane(id)
		if err != nil {
			log.Printf("TmuxDeinitWindows: %v", err)
		}
	}
}

// TmuxInitWindows split current terminal into several windows/panes
// - command output window
// - current agent info
func TmuxInitWindows() (err error) {
	pane, err := TmuxNewPane("h", "", 30, "/bin/cat")
	if err != nil {
		return
	}
	AgentInfoWindow = pane
	TmuxWindows[AgentInfoWindow.ID] = AgentInfoWindow

	pane, err = TmuxNewPane("v", "", 40, "/bin/cat")
	if err != nil {
		return
	}
	AgentOutputWindow = pane
	TmuxWindows[AgentOutputWindow.ID] = AgentOutputWindow

	return
}

// TmuxNewPane split tmux window, and run command in the new pane
// hV: horizontal or vertical split
// target_pane: target_pane tmux index, split this pane
// size: percentage, do not append %
func TmuxNewPane(hV string, target_pane_id string, size int, cmd string) (pane *Emp3r0rPane, err error) {
	if os.Getenv("TMUX") == "" ||
		!util.IsCommandExist("tmux") {

		err = errors.New("You need to run emp3r0r under `tmux`")
		return
	}
	target_pane := TmuxPaneID2Index(target_pane_id)
	if target_pane < 0 {

	}

	job := fmt.Sprintf(`tmux split-window -%s -p %d -P -d -F "#{pane_id}:#{pane_pid}:#{pane_tty}" '%s'`,
		hV, size, cmd)
	if target_pane > 0 {
		job = fmt.Sprintf(`tmux split-window -t %d -%s -p %d -P -d -F "#{pane_id}:#{pane_pid}:#{pane_tty}" '%s'`,
			target_pane, hV, size, cmd)
	}

	out, err := exec.Command("/bin/sh", "-c", job).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("exec tmux: %s\n%v", out, err)
		return
	}
	tmux_result := string(out)
	tmux_res_split := strings.Split(tmux_result, ":")
	if len(tmux_res_split) != 3 {
		err = fmt.Errorf("tmux result cannot be parsed: %s", tmux_result)
		return
	}

	pane = &Emp3r0rPane{}
	pane.ID = tmux_res_split[0]
	pane.PID, err = strconv.Atoi(tmux_res_split[1])
	if err != nil {
		err = fmt.Errorf("parsing pane pid: %v", err)
		return
	}
	tty_path := strings.TrimSpace(tmux_res_split[2])
	tty_file, err := os.OpenFile(tty_path, os.O_RDWR, 0777)
	if err != nil {
		err = fmt.Errorf("open pane tty (%s): %v", tty_path, err)
		return
	}
	pane.FD = tty_file // no need to close files, since CC's interface always needs them

	return
}

// Convert tmux pane's unique ID to index number, for use with select-pane
// returns -1 if failed
func TmuxPaneID2Index(id string) (index int) {
	index = -1

	out, err := exec.Command("/bin/sh", "-c", "tmux list-pane").CombinedOutput()
	if err != nil {
		CliPrintWarning("exec tmux: %s\n%v", out, err)
		return
	}
	tmux_res := strings.Split(string(out), "\n")
	if len(tmux_res) < 1 {
		CliPrintWarning("parse tmux output: no pane found: %s", out)
		return
	}
	for _, line := range tmux_res {
		if strings.Contains(line, id) {
			line_split := strings.Fields(line)
			if len(line_split) < 7 {
				CliPrintWarning("parse tmux output: format error: %s", out)
				return
			}
			idx := strings.TrimSuffix(line_split[0], ":")
			i, err := strconv.Atoi(idx)
			if err != nil {
				CliPrintWarning("parse tmux output: invalid index (%s): %s", idx, out)
				return
			}
			index = i
			break
		}
	}

	return
}

// TmuxNewWindow split tmux window, and run command in the new pane
func TmuxNewWindow(name, cmd string) error {
	if os.Getenv("TMUX") == "" ||
		!util.IsCommandExist("tmux") {
		return errors.New("You need to run emp3r0r under `tmux`")
	}

	tmuxCmd := fmt.Sprintf("tmux new-window -n %s '%s || read'", name, cmd)
	job := exec.Command("/bin/sh", "-c", tmuxCmd)
	out, err := job.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}

	return nil
}

// TmuxSplit split tmux window, and run command in the new pane
func TmuxSplit(hV, cmd string) error {
	if os.Getenv("TMUX") == "" ||
		!util.IsCommandExist("tmux") ||
		!util.IsCommandExist("less") {

		return errors.New("You need to run emp3r0r under `tmux`, and make sure `less` is installed")
	}

	job := fmt.Sprintf("tmux split-window -%s '%s || read'", hV, cmd)

	out, err := exec.Command("/bin/sh", "-c", job).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}

	return nil
}
