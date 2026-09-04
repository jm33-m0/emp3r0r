package gui

import (
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
)

// logMu serializes LogSync file/stderr writes: panic diagnostics and console
// progress can be emitted from several goroutines at once (agent refresher,
// message tunnel, websocket handlers), and interleaved single-write appends
// would corrupt the log lines.
var logMu sync.Mutex

// LogSync writes a line straight to the operator log file, bypassing the
// (asynchronous, channel-backed) logging package. The logging package can
// lose messages when the process exits right after a log call — which is
// exactly when panic/exit diagnostics matter most. Use it for anything that
// must survive an imminent process exit.
func LogSync(format string, a ...any) {
	line := fmt.Sprintf("%s %s\n", time.Now().Format("2006/01/02 15:04:05"), fmt.Sprintf(format, a...))
	logMu.Lock()
	defer logMu.Unlock()
	if f, err := os.OpenFile(live.EmpLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		_, _ = f.WriteString(line)
		_ = f.Close()
	}
	// stderr may be a pty (console pane) after login — fine either way
	_, _ = os.Stderr.WriteString(line)
}

// guiRecover logs a goroutine panic synchronously to the log file and
// optionally reports it to connected frontends. Panics inside goroutines
// that are not recovered would silently kill the whole cc process (the
// runtime prints the trace to stderr, which is the pty after login, and the
// message would be lost) — so every GUI goroutine uses this.
func guiRecover(format string) {
	if r := recover(); r != nil {
		LogSync("%s: panic: %v\n%s", format, r, debug.Stack())
	}
}
