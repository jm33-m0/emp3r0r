package gui

import (
	"errors"
	"os"
	"os/exec"
	"sync"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// errNoShell is returned when keystrokes arrive for a shell that is not
// running.
var errNoShell = errors.New("OS shell is not running")

// guiShellID is the id of the (single) OS shell session offered in the GUI
// sidebar. The backend is written id-agnostically so more shell sessions
// could be added later without protocol changes.
const guiShellID = "0"

// shellSession is one local OS shell: a child process (the operator's
// login shell) attached to its own pty. Unlike the emp3r0r console — which
// lives on the process stdio fds — a shell must be a separate process,
// because the operator may use the GUI console and the OS shell at the same
// time. Keeping it on a dedicated pty gives it a real controlling terminal:
// job control, Ctrl+C/Z, resize (SIGWINCH) and full-screen apps all behave
// like a normal terminal.
type shellSession struct {
	id      string
	master  *os.File
	cmd     *exec.Cmd
	writeMu sync.Mutex
	closed  bool
}

// handleShellOpen starts the OS shell (or re-attaches when one is already
// running, e.g. after the browser tab reconnects) and replies to the client.
func (g *Backend) handleShellOpen(c *wsClient, msg wsMessage) {
	id := msg.ID
	if id == "" {
		id = guiShellID
	}

	g.shellMu.Lock()
	existing := g.shells[id]
	g.shellMu.Unlock()
	if existing != nil {
		// already running: tell the client it can attach, then replay recent
		// output so the terminal is not blank
		g.sendTo(c, map[string]any{"type": "shell_opened", "id": id, "ok": true}, false)
		if buf := g.shellBufSnapshot(id); len(buf) > 0 {
			g.sendTo(c, map[string]any{"type": "shell_out", "id": id, "data": encodeBase64(buf)}, true)
		}
		return
	}

	sess, err := guiSpawnShell(id, msg.Cols, msg.Rows)
	if err != nil {
		logging.Errorf("Open OS shell: %v", err)
		g.sendTo(c, map[string]any{"type": "shell_opened", "id": id, "ok": false, "error": err.Error()}, false)
		return
	}

	g.shellMu.Lock()
	g.shells[id] = sess
	g.shellMu.Unlock()

	logging.Successf("OS shell opened (id %s, pid %d)", id, sess.pid())
	g.sendTo(c, map[string]any{"type": "shell_opened", "id": id, "ok": true}, false)
	go g.shellReadLoop(sess)
}

// shellReadLoop forwards shell output to the frontends until the shell exits.
func (g *Backend) shellReadLoop(sess *shellSession) {
	defer guiRecover("OS shell read loop")
	buf := make([]byte, 32*1024)
	for {
		n, err := sess.master.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			g.shellBufAppend(sess.id, chunk)
			g.broadcast(map[string]any{
				"type": "shell_out",
				"id":   sess.id,
				"data": encodeBase64(chunk),
			}, true)
		}
		if err != nil {
			break
		}
	}
	g.closeShell(sess.id)
	g.broadcast(map[string]any{"type": "shell_closed", "id": sess.id}, false)
	logging.Infof("OS shell (id %s) exited", sess.id)
}

// writeShell forwards operator keystrokes to a running shell.
func (g *Backend) writeShell(id string, data []byte) error {
	g.shellMu.Lock()
	sess := g.shells[id]
	g.shellMu.Unlock()
	if sess == nil {
		return errNoShell
	}
	sess.writeMu.Lock()
	defer sess.writeMu.Unlock()
	_, err := sess.master.Write(data)
	return err
}

// resizeShell applies a new terminal size to a running shell.
func (g *Backend) resizeShell(msg wsMessage) {
	if msg.Cols == 0 || msg.Rows == 0 {
		return
	}
	g.shellMu.Lock()
	sess := g.shells[msg.ID]
	g.shellMu.Unlock()
	if sess != nil {
		_ = guiSetPtySize(sess.master, msg.Cols, msg.Rows)
	}
}

// closeShell terminates a shell session if it is still running.
func (g *Backend) closeShell(id string) {
	g.shellMu.Lock()
	sess := g.shells[id]
	if sess != nil {
		delete(g.shells, id)
	}
	g.shellMu.Unlock()
	if sess == nil {
		return
	}
	sess.writeMu.Lock()
	if !sess.closed {
		sess.closed = true
		if sess.cmd != nil && sess.cmd.Process != nil {
			_ = sess.cmd.Process.Kill()
		}
		_ = sess.master.Close()
	}
	sess.writeMu.Unlock()
}

// closeShells tears down every shell session (GUI shutdown).
func (g *Backend) closeShells() {
	g.shellMu.Lock()
	ids := make([]string, 0, len(g.shells))
	for id := range g.shells {
		ids = append(ids, id)
	}
	g.shellMu.Unlock()
	for _, id := range ids {
		g.closeShell(id)
	}
}

// close kills the shell process and releases the pty.
func (s *shellSession) close() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	if s.master != nil {
		_ = s.master.Close()
	}
}

func (s *shellSession) pid() int {
	if s.cmd != nil && s.cmd.Process != nil {
		return s.cmd.Process.Pid
	}
	return -1
}

func (g *Backend) shellBufAppend(id string, chunk []byte) {
	g.shellBufMu.Lock()
	defer g.shellBufMu.Unlock()
	const maxBuf = 64 * 1024
	buf := append(g.shellBufs[id], chunk...)
	if len(buf) > maxBuf {
		buf = append([]byte(nil), buf[len(buf)-maxBuf:]...)
	}
	g.shellBufs[id] = buf
}

func (g *Backend) shellBufSnapshot(id string) []byte {
	g.shellBufMu.Lock()
	defer g.shellBufMu.Unlock()
	buf := g.shellBufs[id]
	if len(buf) == 0 {
		return nil
	}
	out := make([]byte, len(buf))
	copy(out, buf)
	return out
}
