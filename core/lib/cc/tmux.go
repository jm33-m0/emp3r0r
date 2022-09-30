package cc

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"golang.org/x/crypto/ssh/terminal"
)

// Emp3r0rPane a tmux window/pane that makes emp3r0r CC's interface
type Emp3r0rPane struct {
	Alive    bool   // indicates that pane is not dead
	ID       string // tmux pane unique ID
	WindowID string // tmux window unique ID, indicates the window that the pane lives in
	Title    string // title of pane
	Name     string // intial title of pane, doesn't change even if pane is dead
	TTY      string // eg. /dev/pts/1, write to this file to get your message displayed on this pane
	PID      int    // PID of the process running in tmux pane
	Cmd      string // cmdline of the process
	Width    int    // width of pane, number of chars
	Height   int    // height of pane, number of chars
}

var (
	// home tmux window
	HomeWindow string

	// Console titled "Command"
	CommandPane *Emp3r0rPane

	// Displays system info of selected agent
	AgentInfoPane *Emp3r0rPane

	// Displays agent output, separated from logs
	AgentOutputPane *Emp3r0rPane

	// Displays agent list
	AgentListPane *Emp3r0rPane

	// Displays bash shell for selected agent
	AgentShellPane *Emp3r0rPane

	// SFTP shell for selected agent
	AgentSFTPPane *Emp3r0rPane

	// Put all windows in this map
	TmuxPanes = make(map[string]*Emp3r0rPane)

	// CAT use this cat to replace /bin/cat
	CAT = "emp3r0r-cat"
)

// TmuxInitWindows split current terminal into several windows/panes
// - command output window
// - current agent info
func TmuxInitWindows() (err error) {
	// home tmux window id
	HomeWindow = TmuxCurrentWindow()

	// remain-on-exit for current tmux window
	// "on" is necessary
	TmuxSetOpt(HomeWindow, "remain-on-exit on")

	// main window
	CommandPane = &Emp3r0rPane{}
	CommandPane.Name = "Emp3r0r Console"
	TmuxUpdatePane(CommandPane)

	// pane title
	TmuxSetPaneTitle("Emp3r0r Console", CommandPane.ID)

	// check terminal size, prompt user to run emp3r0r C2 in a bigger window
	w, h, err := TermSize()
	if err != nil {
		CliPrintWarning("Get terminal size: %v", err)
	}
	if w < 180 || h < 40 {
		CliPrintWarning("I need a bigger window, make sure the window size is at least 180x40 (w*h)")
		CliPrintWarning("Please maximize the terminal window if possible")
	}

	// we don't want the tmux pane be killed
	// so easily. Yes, fuck /bin/cat, we use our own cat
	cat := CAT
	if !util.IsFileExist(cat) {
		pwd, e := os.Getwd()
		if e != nil {
			pwd = e.Error()
		}
		err = fmt.Errorf("PWD=%s, check if %s exists. If not, build it", pwd, cat)
		return
	}
	CliPrintInfo("Using %s", cat)

	new_pane := func(
		title,
		place_holder,
		direction,
		from_pane string,
		size_percentage int) (pane *Emp3r0rPane, err error) {

		// system info of selected agent
		pane, err = TmuxNewPane(title, direction, from_pane, size_percentage, cat)
		if err != nil {
			return
		}
		TmuxPanes[pane.ID] = pane
		pane.Printf(false, color.HiYellowString(place_holder))

		pane.Name = title

		return
	}

	// system info of selected agent
	AgentInfoPane, err = new_pane("Agent System Info", "Try `target 0`?", "h", "", 24)
	if err != nil {
		return
	}

	// Agent output
	AgentOutputPane, err = new_pane("Agent Handler", "Command results go below...\n", "h", "", 33)
	if err != nil {
		return
	}

	// Agent List
	AgentListPane, err = new_pane("Agent List", "No agents connected", "", "", 0)
	if err != nil {
		return
	}
	TmuxSetOpt(AgentListPane.WindowID, "remain-on-exit on")

	// check panes
	if AgentListPane == nil ||
		AgentOutputPane == nil ||
		AgentInfoPane == nil {
		return fmt.Errorf("One or more tmux panes failed to initialize:\n%v", TmuxPanes)
	}

	return
}

// returns the index of current pane
// returns -1 when error occurs
func TmuxCurrentPane() (index int) {
	index = -1
	out, err := exec.Command("tmux", "display-message", "-p", `'#P'`).CombinedOutput()
	if err != nil {
		CliPrintWarning("TmuxCurrentPane: %v", err)
		return
	}

	out_str := strings.TrimSpace(string(out))
	index, err = strconv.Atoi(out_str)
	if err != nil {
		return // returns -1 if fail to parse as int
	}
	return
}

func TmuxSwitchWindow(window_id string) (res bool) {
	out, err := exec.Command("/bin/sh", "-c", "tmux select-window -t "+window_id).CombinedOutput()
	if err != nil {
		CliPrintWarning("TmuxSwitchWindow: %v: %s", err, out)
		return
	}
	return true
}

// All panes live in this tmux window,
// returns the unique ID of the window
// returns "" when error occurs
func TmuxCurrentWindow() (id string) {
	out, err := exec.Command("tmux", "display-message", "-p", `'#{window_id}'`).CombinedOutput()
	if err != nil {
		CliPrintWarning("TmuxCurrentWindow: %v", err)
		return
	}

	id = strings.TrimSpace(string(out))
	return
}

func (pane *Emp3r0rPane) Respawn() (err error) {
	defer TmuxUpdatePane(pane)
	out, err := exec.Command("tmux", "respawn-pane",
		"-t", pane.ID, CAT).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Respawning pane (pane_id=%s): %s, %v", pane.ID, out, err)
	}

	return
}

// Printf like printf, but prints to a tmux pane/window
// id: pane unique id
func (pane *Emp3r0rPane) Printf(clear bool, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	if clear {
		err := pane.ClearPane()
		if err != nil {
			CliPrintWarning("Clear pane failed: %v", err)
		}
	}

	if !TmuxSwitchWindow(pane.WindowID) {
		CliPrintWarning("pane '%s' printf: unable to switch to tmux window '%s'",
			pane.Title, pane.WindowID)
	}
	defer TmuxSwitchWindow(HomeWindow)
	TmuxUpdatePane(pane)
	id := pane.ID
	if !pane.Alive {
		CliPrintWarning("Tmux window %s (%s) is dead/gone, respawning...", id, pane.Title)
		err = pane.Respawn()
		if err == nil {
			pane.Printf(clear, format, a...)
		} else {
			CliPrintError("Respawn error: %v", err)
		}
		return
	}

	// print msg
	err := ioutil.WriteFile(pane.TTY, []byte(msg), 0777)
	if err != nil {
		CliPrintWarning("Cannot print on tmux window %s (%s): %v,\n"+
			"printing to main window instead.\n\n",
			id,
			pane.Title,
			err)
		CliPrintWarning(format, a...)
	}
}

func (pane *Emp3r0rPane) ClearPane() (err error) {
	id := pane.ID

	job := fmt.Sprintf("tmux respawn-pane -t %s -k %s", id, pane.Cmd)
	out, err := exec.Command("/bin/sh", "-c", job).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("exec tmux respawn pane: %s\n%v", out, err)
		return
	}

	job = fmt.Sprintf("tmux clear-history -t %s", id)
	out, err = exec.Command("/bin/sh", "-c", job).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("exec tmux clear-history: %s\n%v", out, err)
		return
	}

	// update
	defer TmuxUpdatePane(pane)
	return
}

// PaneDetails Get details of a tmux pane
func (pane *Emp3r0rPane) PaneDetails() (
	is_alive bool,
	title string,
	tty string,
	pid int,
	cmd string,
	width int,
	height int) {

	if pane.ID == "" {
		return
	}
	if pane.WindowID == "" {
		return
	}

	out, err := exec.Command("/bin/sh", "-c",
		fmt.Sprintf("tmux display -p -t %s "+
			`'#{pane_dead}:#{pane_tty}:#{pane_pid}:#{pane_width}:`+
			`#{pane_height}:#{pane_current_command}:#{pane_title}'`,
			pane.ID)).CombinedOutput()
	if err != nil {
		CliPrintWarning("tmux get pane details: %s, %v", out, err)
		return
	}
	out_str := strings.TrimSpace(string(out))

	// parse
	out_split := strings.Split(out_str, ":")
	if len(out_split) < 6 {
		CliPrintWarning("TmuxPaneDetails failed to parse tmux output: %s", out_str)
		return
	}
	is_alive = out_split[0] != "1"
	tty = out_split[1]
	pid, err = strconv.Atoi(out_split[2])
	if err != nil {
		CliPrintWarning("Pane Details: %v", err)
		pid = -1
	}
	width, err = strconv.Atoi(out_split[3])
	if err != nil {
		CliPrintWarning("Pane Details: %v", err)
		width = -1
	}
	height, err = strconv.Atoi(out_split[4])
	if err != nil {
		CliPrintWarning("Pane Details: %v", err)
		height = -1
	}

	// cmd = out_split[5]
	cmd = CAT
	title = out_split[6]
	return
}

// ResizePane resize pane in x/y to number of lines
func (pane *Emp3r0rPane) ResizePane(direction string, lines int) (err error) {
	id := pane.ID
	job := fmt.Sprintf("tmux resize-pane -t %s -%s %d", id, direction, lines)
	out, err := exec.Command("/bin/sh", "-c", job).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("exec tmux resize-pane: %s\n%v", out, err)
		return
	}
	return
}

func TmuxKillWindow(id string) (err error) {
	out, err := exec.Command("tmux", "kill-window", "-t", id).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s\n%v", out, err)
	}
	return
}

func (pane *Emp3r0rPane) KillPane() (err error) {
	id := pane.ID
	job := fmt.Sprintf("tmux kill-pane -t %s", id)
	out, err := exec.Command("/bin/sh", "-c", job).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("exec tmux kill-pane: %s\n%v", out, err)
		return
	}
	return
}

// TmuxDeinitWindows close previously opened tmux windows
func TmuxDeinitWindows() {
	// kill session altogether
	out, err := exec.Command("/bin/sh", "-c", "tmux kill-session -t emp3r0r").CombinedOutput()
	if err != nil {
		CliPrintError("exec tmux kill-session -t emp3r0r: %s\n%v", out, err)
	}
}

// TermSize Get terminal size
func TermSize() (width, height int, err error) {
	width, height, err = terminal.GetSize(int(os.Stdin.Fd()))
	return
}

// Set tmux option of current tmux window
func TmuxSetOpt(index, opt string) (err error) {
	job := fmt.Sprintf("tmux set-option %s", opt)
	out, err := exec.Command("/bin/sh", "-c", job).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("exec tmux set-option %s: %s\n%v", opt, out, err)
		return
	}

	return
}

// TmuxNewPane split tmux window, and run command in the new pane
// hV: horizontal or vertical split
// target_pane: target_pane tmux index, split this pane
// size: percentage, do not append %
func TmuxNewPane(title, hV string, target_pane_id string, size int, cmd string) (pane *Emp3r0rPane, err error) {
	if os.Getenv("TMUX") == "" ||
		!util.IsCommandExist("tmux") {

		err = errors.New("You need to run emp3r0r under `tmux`")
		return
	}
	is_new_window := hV == "" && size == 0

	job := fmt.Sprintf(`tmux split-window -%s -p %d -P -d -F "#{pane_id}:#{pane_pid}:#{pane_tty}:#{window_id}" '%s'`,
		hV, size, cmd)
	if target_pane_id != "" {
		job = fmt.Sprintf(`tmux split-window -t %s -%s -p %d -P -d -F "#{pane_id}:#{pane_pid}:#{pane_tty}:#{window_id}" '%s'`,
			target_pane_id, hV, size, cmd)
	}

	// what if i want to open a new tmux window?
	if is_new_window {
		job = fmt.Sprintf(`tmux new-window -n '%s' -P -d -F "#{pane_id}:#{pane_pid}:#{pane_tty}:#{window_id}" '%s'`,
			title, cmd)
	}

	out, err := exec.Command("/bin/sh", "-c", job).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("exec tmux: %s\n%v", out, err)
		return
	}
	tmux_result := string(out)
	tmux_res_split := strings.Split(tmux_result, ":")
	if len(tmux_res_split) < 3 {
		err = fmt.Errorf("tmux result cannot be parsed:\n%s\n==>\n%s",
			strconv.Quote(job), strconv.Quote(tmux_result))
		return
	}

	pane = &Emp3r0rPane{}
	pane.ID = tmux_res_split[0]
	pane.PID, err = strconv.Atoi(tmux_res_split[1])
	if err != nil {
		err = fmt.Errorf("parsing pane pid: %v", err)
		return
	}
	pane.TTY = strings.TrimSpace(tmux_res_split[2])
	pane.WindowID = strings.TrimSpace(tmux_res_split[3])

	err = TmuxSetPaneTitle(title, pane.ID)
	TmuxUpdatePane(pane)
	return
}

// Sync changes of a pane
func TmuxUpdatePane(pane *Emp3r0rPane) {
	if pane == nil {
		CliPrintWarning("UpdatePane: no pane to update")
		return
	}
	pane.Alive, pane.Title, pane.TTY, pane.PID, pane.Cmd, pane.Width, pane.Height = pane.PaneDetails()
	if pane.Title == "" {
		pane.Title = pane.Name
	}
}

func TmuxSetPaneTitle(title, pane_id string) error {
	// set pane title
	tmux_cmd := []string{"select-pane", "-t", pane_id, "-T", title}

	out, err := exec.Command("tmux", tmux_cmd...).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("%s\n%v", out, err)
	}

	return err
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
