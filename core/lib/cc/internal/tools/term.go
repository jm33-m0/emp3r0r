package tools

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

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

// CopyToClipboard copy data to clipboard using xsel -b
func CopyToClipboard(data []byte) {
	exe := "xsel"
	cmd := exec.Command("xsel", "-bi")
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		exe = "wl-copy"
		cmd = exec.Command("wl-copy")
	} else if os.Getenv("DISPLAY") == "" {
		logging.Warningf("Neither Wayland nor X11 is running, CopyToClipboard will abort")
		return
	}
	if !util.IsCommandExist(exe) {
		logging.Warningf("%s not installed", exe)
		return
	}
	stdin, stdinErr := cmd.StdinPipe()
	if stdinErr != nil {
		logging.Warningf("CopyToClipboard read stdin: %v", stdinErr)
		return
	}
	go func() {
		defer stdin.Close()
		_, _ = stdin.Write(data)
	}()

	stdinErr = cmd.Run()
	if stdinErr != nil {
		logging.Warningf("CopyToClipboard: %v", stdinErr)
	}
	logging.Infof("Copied to clipboard")
}
