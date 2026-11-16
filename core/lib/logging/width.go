package logging

import (
	"os"
	"strconv"
	"sync/atomic"

	"golang.org/x/term"
)

// defaultRenderWidth is used when the output is neither a terminal nor has a
// COLUMNS hint. It avoids glamour's 80-column default, which is too narrow for
// tmux panes and terminal emulators on modern screens.
const defaultRenderWidth = 120

var renderWidth atomic.Int64

// SetRenderWidth overrides the width used by RenderMarkdown. The detection loop
// writes to a log file, so the console passes the width of the tmux pane that
// tails the log.
func SetRenderWidth(width int) {
	if width > 0 {
		renderWidth.Store(int64(width))
		return
	}
	renderWidth.Store(0)
}

// TerminalWidth returns the width RenderMarkdown should use. An explicit
// SetRenderWidth wins, then the size of stdout/stdin/stderr when one of them is
// a terminal, then COLUMNS, then a wide fallback. A width of 0 makes glamour use
// its own 80-column default, so never return 0.
func TerminalWidth() int {
	if width := int(renderWidth.Load()); width > 0 {
		return width
	}
	for _, file := range []*os.File{os.Stdout, os.Stdin, os.Stderr} {
		if !term.IsTerminal(int(file.Fd())) {
			continue
		}
		width, _, err := term.GetSize(int(file.Fd()))
		if err == nil && width > 0 {
			return width
		}
	}
	if width, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && width > 0 {
		return width
	}
	return defaultRenderWidth
}
