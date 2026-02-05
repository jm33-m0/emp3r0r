package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	terminal "golang.org/x/term"
)

// TmuxPane a tmux window/pane that makes emp3r0r CC's interface
type TmuxPane struct {
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
	// TermWidth
	TermWidth int

	// TermHeight
	TermHeight int

	// home tmux window
	HomeWindow string

	// Console titled "Command"
	CommandPane *TmuxPane

	// Displays agent output, separated from logs
	OutputPane *TmuxPane

	// Displays agent list
	AgentListPane *TmuxPane

	// Displays bash shell for selected agent
	AgentShellPane *TmuxPane

	// SFTP shell for selected agent
	AgentSFTPPane *TmuxPane

	// Put all windows in this map
	TmuxPanes = make(map[string]*TmuxPane)

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
	if setoptErr := TmuxSetOpt(HomeWindow, "remain-on-exit on"); setoptErr != nil {
		return fmt.Errorf("setting home window as persistent: %v", setoptErr)
	}

	// main window
	CommandPane = &TmuxPane{}
	CommandPane.Name = "Emp3r0r Console"
	CommandPane.ID = TmuxCurrentPane()
	CommandPane.WindowID = TmuxCurrentWindow()
	TmuxUpdatePane(CommandPane)

	// pane title
	if setPaneTitleErr := CommandPane.SetTitle("Emp3r0r Console"); setPaneTitleErr != nil {
		return fmt.Errorf("setting title for Emp3r0r Console pane: %v", setPaneTitleErr)
	}

	// check terminal size, prompt user to run emp3r0r C2 in a bigger window
	TermWidth, TermHeight, err = TermSize()
	if err != nil {
		logging.Warningf("Get terminal size: %v", err)
	}

	// we don't want the tmux pane be killed
	// so easily. Yes, fuck /bin/cat, we use our own cat
	cat := CAT
	if !util.IsExist(cat) {
		pwd, e := os.Getwd()
		if e != nil {
			pwd = e.Error()
		}
		err = fmt.Errorf("PWD=%s, check if %s exists. If not, build it", pwd, cat)
		return
	}
	logging.Debugf("Using %s", cat)

	new_pane := func(
		title,
		place_holder,
		direction,
		from_pane string,
		size_percentage int,
	) (pane *TmuxPane, err error) {
		// system info of selected agent
		pane, err = TmuxNewPane(title, direction, from_pane, size_percentage, cat)
		if err != nil {
			return
		}
		TmuxPanes[pane.ID] = pane
		pane.Printf(false, "%s", color.HiYellowString(place_holder))

		pane.Name = title

		return
	}

	// if window size is too small, use simplified layout
	use_simplified_layout := false
	if TermWidth < 180 || TermHeight < 40 {
		logging.Warningf("Window size is too small, please resize the window to at least 180x40")
		logging.Infof("Current size: %d x %d. Using simplified layout", TermWidth, TermHeight)
		use_simplified_layout = true
	}

	// Agent output
	OutputPane, err = new_pane("Output", "Saving to emp3r0r.log...\n", "h", "", 50)
	if err != nil {
		return
	}

	if use_simplified_layout {
		// Agent List
		AgentListPane, err = new_pane("Agent List", "No agents connected", "", "", 0)
		if err != nil {
			return
		}
		if setOptErr := TmuxSetOpt(AgentListPane.WindowID, "remain-on-exit on"); setOptErr != nil {
			return fmt.Errorf("TmuxSetOpt: %v", setOptErr)
		}
	} else {
		// Agent List
		AgentListPane, err = new_pane("Agent List", "No agents connected", "v", "", 40)
		if err != nil {
			return
		}
	}

	// check panes
	if AgentListPane == nil ||
		OutputPane == nil {
		return fmt.Errorf("one or more tmux panes failed to initialize:\n%v", TmuxPanes)
	}

	return
}

func TmuxDisplay(msg string) (res string) {
	out, execErr := exec.Command("tmux", "display-message", "-p", msg).CombinedOutput()
	if execErr != nil {
		logging.Warningf("TmuxDisplay: %v", execErr)
		return
	}

	return string(out)
}

// TmuxWindowSize size in chars, of the current tmux window/tab
func TmuxWindowSize() (x, y int) {
	// initialize
	x = -1
	y = x

	// tmux display
	tmux_display := func(msg string) (res int) {
		out_str := strings.TrimSpace(TmuxDisplay(msg))
		out_str = strings.ReplaceAll(out_str, "'", "") // we get '123' so we have to remove the quotes
		res, err := strconv.Atoi(out_str)
		if err != nil {
			logging.Debugf("Unable to get %s (%s): %v", msg, out_str, err)
			return -1 // returns -1 if fail to parse as int
		}
		logging.Debugf("TmuxWindowSize %s -> %s", msg, out_str)
		return
	}
	x = tmux_display(`#{window_width}`)
	y = tmux_display(`#{window_height}`)

	return
}

// returns the index of current pane
// returns -1 when error occurs
func TmuxCurrentPane() (pane_id string) {
	out, execErr := exec.Command("tmux", "display-message", "-p", "#{pane_id}").CombinedOutput()
	if execErr != nil {
		logging.Warningf("TmuxCurrentPane: %v", execErr)
		return
	}

	pane_id = strings.TrimSpace(string(out))
	return
}

func TmuxSwitchWindow(window_id string) (res bool) {
	out, cmdErr := exec.Command("/bin/sh", "-c", "tmux select-window -t "+window_id).CombinedOutput()
	if cmdErr != nil {
		logging.Warningf("TmuxSwitchWindow: %v: %s", cmdErr, out)
		return
	}
	return true
}

// All panes live in this tmux window,
// returns the unique ID of the window
// returns "" when error occurs
func TmuxCurrentWindow() (id string) {
	out, cmdErr := exec.Command("tmux", "display-message", "-p", "#{window_id}").CombinedOutput()
	if cmdErr != nil {
		logging.Warningf("TmuxCurrentWindow: %v", cmdErr)
		return
	}

	id = strings.TrimSpace(string(out))
	return
}

func (pane *TmuxPane) SetTitle(title string) (err error) {
	list_panes := func() string {
		tmuxCmd := []string{"list-panes"}
		out, err := exec.Command("tmux", tmuxCmd...).CombinedOutput()
		if err != nil {
			return fmt.Sprintf("exec tmux list-panes: %s\n%v", out, err)
		}
		return string(out)
	}

	// set pane title
	tmux_cmd := []string{"select-pane", "-t", pane.ID, "-T", title}

	out, err := exec.Command("tmux", tmux_cmd...).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("setting pane %s title to %s: %s (%v)\nCurrent panes:\n%s",
			pane.ID, title, out, err, list_panes())
	}

	return err
}

func (pane *TmuxPane) Respawn() (err error) {
	defer TmuxUpdatePane(pane)
	out, err := exec.Command("tmux", "respawn-pane",
		"-t", pane.ID, CAT).CombinedOutput()
	if err != nil {
		return fmt.Errorf("respawning pane (pane_id=%s): %s, %v", pane.ID, out, err)
	}

	return
}

// Printf like printf, but prints to a tmux pane/window
// id: pane unique id
func (pane *TmuxPane) Printf(clear bool, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	if clear {
		clearPaneErr := pane.ClearPane()
		if clearPaneErr != nil {
			logging.Warningf("Clear pane failed: %v", clearPaneErr)
		}
	}

	TmuxUpdatePane(pane)
	id := pane.ID
	if !pane.Alive {
		logging.Warningf("Tmux window %s (%s) is dead/gone, respawning...", id, pane.Title)
		err := pane.Respawn()
		if err == nil {
			pane.Printf(clear, format, a...)
		} else {
			logging.Errorf("Respawn error: %v", err)
		}
		return
	}

	// print msg
	werr := os.WriteFile(pane.TTY, []byte(msg), 0o777)
	if werr != nil {
		logging.Warningf("Cannot print on tmux window %s (%s): %v,\n"+
			"printing to main window instead.\n\n",
			id,
			pane.Title,
			werr)
		logging.Warningf(format, a...)
	}
}

func (pane *TmuxPane) ClearPane() (err error) {
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
func (pane *TmuxPane) PaneDetails() (
	is_alive bool,
	title string,
	tty string,
	pid int,
	cmd string,
	width int,
	height int,
) {
	if pane.ID == "" {
		return
	}
	if pane.WindowID == "" {
		return
	}

	out, err := exec.Command("/bin/sh", "-c",
		fmt.Sprintf("tmux display-message -p -t %s "+
			`'#{pane_dead}:#{pane_tty}:#{pane_pid}:#{pane_width}:`+
			`#{pane_height}:#{pane_current_command}:#{pane_title}'`,
			pane.ID)).CombinedOutput()
	if err != nil {
		logging.Warningf("tmux get pane details: %s, %v", out, err)
		return
	}
	out_str := strings.TrimSpace(string(out))

	// parse
	out_split := strings.Split(out_str, ":")
	if len(out_split) < 6 {
		logging.Warningf("TmuxPaneDetails failed to parse tmux output: %s", out_str)
		return
	}
	is_alive = out_split[0] != "1"
	tty = out_split[1]
	pid, err = strconv.Atoi(out_split[2])
	if err != nil {
		logging.Warningf("Pane Details: %v", err)
		pid = -1
	}
	width, err = strconv.Atoi(out_split[3])
	if err != nil {
		logging.Warningf("Pane Details: %v", err)
		width = -1
	}
	height, err = strconv.Atoi(out_split[4])
	if err != nil {
		logging.Warningf("Pane Details: %v", err)
		height = -1
	}

	// cmd = out_split[5]
	cmd = CAT
	title = out_split[6]
	return
}

// ResizePane resize pane in x/y to number of lines
func (pane *TmuxPane) ResizePane(direction string, lines int) (err error) {
	id := pane.ID
	job := fmt.Sprintf("tmux resize-pane -t %s -%s %d", id, direction, lines)
	logging.Debugf("Resizing pane %s: %s", pane.Title, job)
	out, err := exec.Command("/bin/sh", "-c", job).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("exec tmux resize-pane: %s\n%v", out, err)
		return
	}
	return
}

func (pane *TmuxPane) KillPane() (err error) {
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
	// do not kill tmux windows if debug is enabled
	if logging.TmuxPersistence {
		return
	}

	time.Sleep(2 * time.Second)
	// kill session altogether
	out, err := exec.Command("/bin/sh", "-c", "tmux kill-session -t emp3r0r").CombinedOutput()
	if err != nil {
		logging.Errorf("exec tmux kill-session -t emp3r0r: %s\n%v", out, err)
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
func TmuxNewPane(title, hV string, target_pane_id string, size int, cmd string) (pane *TmuxPane, err error) {
	if os.Getenv("TMUX") == "" ||
		!util.IsCommandExist("tmux") {

		err = errors.New("you need to run emp3r0r under `tmux`")
		return
	}
	is_new_window := hV == "" && size == 0

	job := fmt.Sprintf(`tmux split-window -%s -l %d%% -P -d -F "#{pane_id}:#{pane_pid}:#{pane_tty}:#{window_id}" '%s'`,
		hV, size, cmd)
	if target_pane_id != "" {
		job = fmt.Sprintf(`tmux split-window -t %s -%s -l %d%% -P -d -F "#{pane_id}:#{pane_pid}:#{pane_tty}:#{window_id}" '%s'`,
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

	pane = &TmuxPane{}
	pane.ID = tmux_res_split[0]
	pane.PID, err = strconv.Atoi(tmux_res_split[1])
	if err != nil {
		err = fmt.Errorf("parsing pane pid: %v", err)
		return
	}
	pane.TTY = strings.TrimSpace(tmux_res_split[2])
	pane.WindowID = strings.TrimSpace(tmux_res_split[3])

	err = pane.SetTitle(title)
	TmuxUpdatePane(pane)
	return
}

// Sync changes of a pane
func TmuxUpdatePane(pane *TmuxPane) {
	if pane == nil {
		logging.Warningf("UpdatePane: no pane to update")
		return
	}
	pane.Alive, pane.Title, pane.TTY, pane.PID, pane.Cmd, pane.Width, pane.Height = pane.PaneDetails()
	if pane.Title == "" {
		pane.Title = pane.Name
	}
}

// TmuxSetWindowTitle set tmux window title, which is the title shown in tmux status bar
func TmuxSetWindowTitle(title, window_id string) error {
	// set pane title
	tmux_cmd := []string{"rename-window", "-t", window_id, title}

	out, err := exec.Command("tmux", tmux_cmd...).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("%s\n%v", out, err)
	}

	return err
}

// TmuxSetStatusRight set tmux status right, which is the status shown on the right side of tmux status bar
func TmuxSetStatusRight(format string, a ...any) error {
	tmuxCmd := fmt.Sprintf("tmux set-option -g status-right ' #{?client_prefix,C-x,} %s'", fmt.Sprintf(format, a...))
	job := exec.Command("/bin/sh", "-c", tmuxCmd)
	out, err := job.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s\n%v", out, err)
	}
	return nil
}

// TmuxNewWindow run command in a new window
func TmuxNewWindow(name, cmd string) error {
	if os.Getenv("TMUX") == "" ||
		!util.IsCommandExist("tmux") {
		return errors.New("you need to run emp3r0r under `tmux`")
	}

	tmuxCmd := fmt.Sprintf("tmux new-window -n %s '%s'", name, cmd)
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
		!util.IsCommandExist("tmux") {
		return errors.New("you need to run emp3r0r under tmux")
	}

	job := fmt.Sprintf("tmux split-window -%s '%s || read'", hV, cmd)

	out, err := exec.Command("/bin/sh", "-c", job).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}

	return nil
}

// FitPanes adjust width of panes to fit them in the terminal window
// triggered by agent output
func FitPanes(output_pane_x int) {
	TmuxUpdatePanes()
	// update panes
	defer TmuxUpdatePanes()

	// in this case no need to resize
	if output_pane_x <= OutputPane.Width {
		logging.Debugf("No need to fit panes")
		return
	}

	TermWidth, TermHeight = TmuxWindowSize()
	if TermHeight < 0 || TermWidth < 0 {
		logging.Warningf("Unable to get terminal size")
		return
	}

	// if Output pane too wide
	if output_pane_x >= TermWidth {
		logging.Warningf("Terminal too narrow (%d chars)", TermWidth)
		return
	}

	// resize
	target_width := output_pane_x - OutputPane.Width
	CommandPane.ResizePane("L", target_width)
	logging.Debugf("Resizing agent handler pane %d-%d=%d chars to the left",
		output_pane_x, OutputPane.Width, target_width)
}

func TmuxUpdatePanes() {
	TmuxUpdatePane(CommandPane)
	TmuxUpdatePane(OutputPane)
}

// ResetPaneLayout resets all panes to their default layout proportions
func ResetPaneLayout() error {
	TmuxUpdatePanes()

	// get terminal size
	TermWidth, TermHeight := TmuxWindowSize()
	if TermHeight < 0 || TermWidth < 0 {
		logging.Warningf("Unable to get terminal size for layout reset")
		return fmt.Errorf("unable to get terminal size")
	}

	// Calculate default sizes (CommandPane should be ~50% width)
	target_command_width := TermWidth / 2

	// Resize CommandPane to target width if it differs significantly
	if abs(CommandPane.Width-target_command_width) > 5 {
		width_diff := target_command_width - CommandPane.Width
		if width_diff > 0 {
			CommandPane.ResizePane("R", width_diff)
		} else {
			CommandPane.ResizePane("L", -width_diff)
		}
		logging.Debugf("Reset CommandPane width to %d (was %d)", target_command_width, CommandPane.Width)
	}

	// Update panes after resizing
	TmuxUpdatePanes()
	return nil
}

// abs returns absolute value of an integer
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
