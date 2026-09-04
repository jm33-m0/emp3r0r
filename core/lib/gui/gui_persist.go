package gui

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// guiSavedSession is what guiSaveSessionCreds stores: the connection command
// parameters of the last successful login, so a later daemon start can
// reconnect automatically — the operator never has to paste the WireGuard
// connection command again, no matter how the previous daemon went away.
type guiSavedSession struct {
	SavedAt time.Time `json:"savedAt"`
	Creds   Creds     `json:"creds"`
}

func guiWorkspaceDir() string {
	if live.EmpLogFile != "" {
		return filepath.Dir(live.EmpLogFile)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".emp3r0r")
	}
	return "."
}

// sessionFilePathOverride lets tests relocate the session file.
var sessionFilePathOverride func() string

func guiSessionFilePath() string {
	if sessionFilePathOverride != nil {
		return sessionFilePathOverride()
	}
	return filepath.Join(guiWorkspaceDir(), "gui_session.json")
}

// guiSaveSessionCreds remembers the last successful connection (0600, next to
// emp3r0r.log). Removed only when the operator exits on purpose (Exit button /
// `exit` in the console), never when the daemon is killed or crashes — so a
// dead daemon can be restarted straight back into the same session.
func guiSaveSessionCreds(creds Creds) {
	dir := filepath.Dir(guiSessionFilePath())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	b, err := json.MarshalIndent(guiSavedSession{SavedAt: time.Now(), Creds: creds}, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(guiSessionFilePath(), b, 0o600); err != nil {
		logging.Warningf("Could not save GUI session: %v", err)
	}
}

func guiLoadSessionCreds() (Creds, bool) {
	b, err := os.ReadFile(guiSessionFilePath())
	if err != nil {
		return Creds{}, false
	}
	var s guiSavedSession
	if json.Unmarshal(b, &s) != nil || s.Creds.C2Host == "" ||
		s.Creds.ServerWgIP == "" || s.Creds.OperatorWgKey == "" {
		return Creds{}, false
	}
	return s.Creds, true
}

func ClearSession() {
	_ = os.Remove(guiSessionFilePath())
}

// parseLastGuiRun scans the operator log for the most recent GUI daemon start
// and returns its URL (with session token) and pid.
func parseLastGuiRun(logText string) (url string, pid int, ok bool) {
	var rawURL, rawPID string
	for _, line := range strings.Split(logText, "\n") {
		if i := strings.Index(line, "GUI server listening on "); i >= 0 {
			rest := line[i+len("GUI server listening on "):]
			if j := strings.Index(rest, ", opening browser"); j >= 0 {
				rawURL = strings.TrimSpace(rest[:j])
			}
		}
		if i := strings.Index(line, "GUI waiting for operator session (pid "); i >= 0 {
			rest := line[i+len("GUI waiting for operator session (pid "):]
			if j := strings.Index(rest, ")"); j >= 0 {
				rawPID = strings.TrimSpace(rest[:j])
			}
		}
	}
	if rawURL == "" || rawPID == "" {
		return "", 0, false
	}
	p, err := strconv.Atoi(rawPID)
	if err != nil || p <= 0 {
		return "", 0, false
	}
	return rawURL, p, true
}

// ReattachIfRunning is called at the very start of a new GUI invocation.
// If a previous GUI daemon is still alive (its pid + URL are in the log), it
// reopens that URL and returns true: the operator lands back in the exact
// same session — console, WireGuard tunnel and all — without starting a
// second daemon and without re-entering any connection command.
func ReattachIfRunning() bool {
	logFile := live.EmpLogFile
	if logFile == "" {
		logFile = filepath.Join(guiWorkspaceDir(), "emp3r0r.log")
	}
	b, err := os.ReadFile(logFile)
	if err != nil {
		return false
	}
	url, pid, ok := parseLastGuiRun(string(b))
	if !ok || pid == os.Getpid() {
		return false
	}
	// alive? (signal 0 just probes; EPERM would mean it exists too)
	if err := syscall.Kill(pid, 0); err != nil {
		return false
	}
	logging.Successf("emp3r0r GUI is already running (pid %d):", pid)
	logging.Successf("    %s", url)
	logging.Infof("Reusing the live session — its WireGuard tunnel and console are still up.")
	launchBrowser(url)
	return true
}

// launchBrowser opens url in the operator's default browser, if any.
func launchBrowser(url string) {
	browser := ""
	for _, b := range []string{"xdg-open", "sensible-browser", "open"} {
		if p, err := exec.LookPath(b); err == nil {
			browser = p
			break
		}
	}
	if browser == "" {
		fmt.Printf("Open %s manually (no browser launcher found)\n", url)
		return
	}
	cmd := exec.Command(browser, url)
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		logging.Warningf("Failed to launch browser: %v", err)
	}
}
