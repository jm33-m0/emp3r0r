package gui

import (
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// startSession performs the full operator login sequence after the login box
// (or the saved-session auto-login) has produced credentials:
//
//  1. host.Connect: WireGuard tunnel up, operator config downloaded & loaded,
//     operator background jobs started (all owned by the operator host)
//  2. start the real interactive console on a pty, plus background UI jobs
//
// Errors are reported to the caller (login_result) so the login box can
// retry after a typo; the host cleans its own side up on failure.
func (g *Backend) startSession(creds Creds) (err error) {
	if g.host == nil {
		return fmt.Errorf("gui: no operator console host")
	}
	LogSync("login: connecting to C2 %s (WireGuard + config)", creds.C2Host)
	if err = g.host.Connect(creds); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	LogSync("login: operator connected, config loaded")

	// remember the login so the frontend can show connection info
	g.sessionMu.Lock()
	g.connected = true
	g.creds = creds
	g.sessionMu.Unlock()

	if err = g.startConsoleSession(); err != nil {
		g.sessionMu.Lock()
		g.connected = false
		g.sessionMu.Unlock()
		return fmt.Errorf("start console: %w", err)
	}
	LogSync("login complete: console session is running")
	return nil
}

// startConsoleSession runs the actual operator console (reeflective readline +
// cobra command tree, provided by the operator host) on a fresh pty and wires
// the pty to the GUI websocket clients.
func (g *Backend) startConsoleSession() error {
	// One console session per login: if a pty is already live (e.g. a second
	// login raced in before g.connecting was set), refuse instead of dup2-ing
	// a fresh pty over fds 0/1/2 while the previous console still runs.
	g.sessionMu.Lock()
	if g.ptyMaster != nil {
		g.sessionMu.Unlock()
		return fmt.Errorf("console session is already running")
	}
	g.sessionMu.Unlock()

	// operator console setup (modules, prompt, history) — runs once per process
	g.host.ConfigureConsole()

	// allocate the pty the console will live on
	master, slave, err := guiOpenPty()
	if err != nil {
		return err
	}
	if err = guiAttachPty(slave); err != nil {
		master.Close()
		slave.Close()
		return err
	}
	_ = slave.Close()

	// The console must render ANSI colors exactly like the tmux CLI does.
	// fatih/color decided at process init whether stdout was a terminal; when
	// the GUI is launched from a wrapper/script/desktop its stdout was not a
	// tty at that point, so NoColor defaulted to true and prompts/logs came
	// out plain. Now that stdout is the console pty (a real tty), re-enable
	// colors and make sure TERM advertises them for anything that checks it.
	color.NoColor = false
	_ = os.Setenv("TERM", "xterm-256color")

	g.sessionMu.Lock()
	g.ptyMaster = master
	g.sessionMu.Unlock()
	LogSync("console session: pty opened & attached (fd 0/1/2)")

	// default size until the browser tells us its real one; handleResize may
	// update lastResize from a websocket goroutine, so read it under the lock
	g.sessionMu.Lock()
	size := g.lastResize
	if size.Cols == 0 || size.Rows == 0 {
		size = termSize{Cols: 120, Rows: 30}
		g.lastResize = size
	}
	g.sessionMu.Unlock()
	_ = guiSetPtySize(master, size.Cols, size.Rows)

	// pty master -> websocket clients
	go g.ptyReadLoop(master)

	// run the interactive console (blocking; it reads/writes the pty slave).
	// consoleRunning flips to true now (before the goroutine) so that any
	// "state" frame sent after this point — the login broadcast or a fresh
	// page (re)load — reports an accurate console status.
	g.consoleRunning.Store(true)

	// If it ever dies (panic, unexpected error), the GUI stays up so the
	// operator can read the error in the log pane and quit cleanly with the
	// Exit button — the process must never die silently.
	go func() {
		defer func() {
			g.consoleRunning.Store(false)
			g.broadcast(map[string]any{"type": "console_closed"}, false)
			LogSync("Console exited — GUI stays up; use the Exit button to quit")
		}()
		defer guiRecover("operator console session")

		LogSync("console session: operator console starting")
		logging.Successf("Console is live in the GUI command pane (type `help` to get started)")
		if err := g.host.RunConsole(); err != nil {
			LogSync("Console exited with error: %v", err)
			logging.Errorf("Console exited with error: %v", err)
		}
		LogSync("console session: operator console returned")
	}()
	return nil
}

// ptyReadLoop forwards pty master output to all connected frontends (base64
// encoded, so arbitrary bytes survive JSON).
func (g *Backend) ptyReadLoop(master *os.File) {
	defer guiRecover("console pty read loop")
	buf := make([]byte, 32*1024)
	for {
		n, err := master.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			g.bufferPtyOut(chunk)
			g.broadcast(map[string]any{
				"type": "pty_out",
				"data": base64.StdEncoding.EncodeToString(chunk),
			}, true)
		}
		if err != nil {
			g.sessionMu.Lock()
			still := g.ptyMaster == master
			g.sessionMu.Unlock()
			if still {
				logging.Debugf("pty read loop ended: %v", err)
			}
			return
		}
	}
}

// writePty sends operator keystrokes (from the browser xterm) into the pty.
func (g *Backend) writePty(data []byte) error {
	g.sessionMu.Lock()
	master := g.ptyMaster
	g.sessionMu.Unlock()
	if master == nil {
		return fmt.Errorf("console session is not running")
	}
	g.ptyWriteMu.Lock()
	defer g.ptyWriteMu.Unlock()
	_, err := master.Write(data)
	return err
}

// bufferPtyOut keeps a small ring of recent pty output so a frontend that
// attaches after the console started (term_ready) still receives the current
// prompt instead of a blank screen.
func (g *Backend) bufferPtyOut(chunk []byte) {
	g.ptyBufMu.Lock()
	defer g.ptyBufMu.Unlock()
	const maxBuf = 128 * 1024
	g.ptyBuf = append(g.ptyBuf, chunk...)
	if len(g.ptyBuf) > maxBuf {
		g.ptyBuf = append([]byte(nil), g.ptyBuf[len(g.ptyBuf)-maxBuf:]...)
	}
}

// localCdn2ProxyHost is used by the gui login flow when --cdn2proxy was passed
// to the cc binary: after config load we know the C2 h2 port to relay to.
func guiStartCdn2Proxy(proxyPort string) {
	go func() {
		logFile, openErr := os.OpenFile("/tmp/ws.log", os.O_CREATE|os.O_RDWR, 0o600)
		if openErr != nil {
			logging.Errorf("OpenFile: %v", openErr)
			return
		}
		h2 := live.RuntimeConfig.CCH2Port
		if h2 == "" || h2 == "0" {
			h2 = "443"
		}
		logging.Infof("Starting cdn2proxy server on %s, relaying to 127.0.0.1:%s", proxyPort, h2)
		if err := startCdn2ProxyServer(proxyPort, "127.0.0.1:"+h2, logFile); err != nil {
			logging.Errorf("CDN StartServer: %v", err)
		}
	}()
}

var _ = time.Second // keep time import when unused
